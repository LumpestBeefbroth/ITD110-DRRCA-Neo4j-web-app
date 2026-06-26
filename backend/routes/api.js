const express = require('express');
const crypto = require('crypto');
const { neo4j, getSession, verifyConnection } = require('../config/db');

const router = express.Router();
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();

const NODE_TYPES = {
  communities: {
    label: 'Community',
    fields: {
      name: 'string',
      population: 'number',
      vulnerabilityLevel: 'string'
    }
  },
  hazardZones: {
    label: 'HazardZone',
    fields: {
      name: 'string',
      type: 'string',
      riskLevel: 'string'
    }
  },
  evacuationCenters: {
    label: 'EvacuationCenter',
    fields: {
      name: 'string',
      capacity: 'number',
      status: 'string'
    }
  },
  resources: {
    label: 'Resource',
    fields: {
      type: 'string',
      quantity: 'number'
    }
  },
  incidentReports: {
    label: 'IncidentReport',
    fields: {
      title: 'string',
      severity: 'string',
      description: 'string',
      reportedAt: 'string'
    }
  },
  preparednessItems: {
    label: 'PreparednessItem',
    fields: {
      title: 'string',
      status: 'string',
      notes: 'string'
    }
  }
};

const APP_LABELS = ['Community', 'HazardZone', 'EvacuationCenter', 'Resource', 'IncidentReport', 'PreparednessItem'];

const LABEL_TO_TYPE = Object.fromEntries(
  Object.entries(NODE_TYPES).map(([type, config]) => [config.label, type])
);

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const passwordHash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, 'sha512')
    .toString('hex');

  return { salt, passwordHash };
}

function verifyPassword(password, salt, expectedHash) {
  const { passwordHash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(passwordHash, 'hex'), Buffer.from(expectedHash, 'hex'));
}

function userToJson(userNode) {
  const user = toNative(userNode.properties);
  const isAdmin = user.role === 'admin';
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: isAdmin ? 'admin' : user.role || 'user',
    isAdmin,
    createdAt: user.createdAt
  };
}

function createSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getNodeConfig(type) {
  const config = NODE_TYPES[type];
  if (!config) {
    const error = new Error(`Unsupported node type: ${type}`);
    error.status = 400;
    throw error;
  }
  return config;
}

function normalizeProperties(type, rawProperties = {}) {
  const { fields } = getNodeConfig(type);
  const properties = {};

  for (const [field, fieldType] of Object.entries(fields)) {
    if (rawProperties[field] === undefined || rawProperties[field] === null || rawProperties[field] === '') {
      continue;
    }

    if (fieldType === 'number') {
      const numberValue = Number(rawProperties[field]);
      if (Number.isNaN(numberValue)) {
        const error = new Error(`${field} must be a valid number`);
        error.status = 400;
        throw error;
      }
      properties[field] = neo4j.int(numberValue);
    } else {
      properties[field] = String(rawProperties[field]).trim();
    }
  }

  return properties;
}

function toNative(value) {
  if (neo4j.isInt(value)) {
    return value.toNumber();
  }

  if (Array.isArray(value)) {
    return value.map(toNative);
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [key, toNative(nestedValue)])
    );
  }

  return value;
}

function nodeToJson(node) {
  if (!node) return null;
  const labels = node.labels || [];
  const label = labels[0];

  return {
    id: node.elementId,
    type: LABEL_TO_TYPE[label] || label,
    label,
    properties: toNative(node.properties)
  };
}

function relationshipToJson(relationship) {
  return {
    id: relationship.elementId,
    type: relationship.type,
    startNodeId: relationship.startNodeElementId,
    endNodeId: relationship.endNodeElementId,
    properties: toNative(relationship.properties)
  };
}

function idsFrom(value) {
  if (!value) return [];
  return Array.isArray(value) ? value.filter(Boolean).map(String) : [String(value)];
}

function listParam() {
  return APP_LABELS;
}

async function writeAudit(tx, userId, action, entityType, entityName) {
  await tx.run(
    `
    MATCH (u:AppUser {id: $userId})
    CREATE (u)-[:OWNS]->(:AuditLog {
      action: $action,
      entityType: $entityType,
      entityName: $entityName,
      createdAt: datetime()
    })
    `,
    { userId, action, entityType, entityName: entityName || 'Unnamed record' }
  );
}

async function applyRelationships(tx, type, nodeId, relationships = {}, replaceExisting = true) {
  const userId = relationships.userId;

  if (type === 'communities') {
    if (replaceExisting && Object.prototype.hasOwnProperty.call(relationships, 'hazardZoneId')) {
      await tx.run(
        'MATCH (c:Community) WHERE elementId(c) = $nodeId MATCH (c)-[r:LOCATED_IN]->(:HazardZone) DELETE r',
        { nodeId }
      );
    }
    if (relationships.hazardZoneId) {
      await tx.run(
        `
        MATCH (c:Community)
        MATCH (z:HazardZone)
        WHERE elementId(c) = $nodeId AND elementId(z) = $hazardZoneId
        MERGE (c)-[:LOCATED_IN]->(z)
        `,
        { nodeId, hazardZoneId: String(relationships.hazardZoneId), userId }
      );
    }

    if (replaceExisting && Object.prototype.hasOwnProperty.call(relationships, 'evacuationCenterId')) {
      await tx.run(
        'MATCH (c:Community) WHERE elementId(c) = $nodeId MATCH (c)-[r:ASSIGNED_TO]->(:EvacuationCenter) DELETE r',
        { nodeId }
      );
    }
    if (relationships.evacuationCenterId) {
      await tx.run(
        `
        MATCH (c:Community)
        MATCH (e:EvacuationCenter)
        WHERE elementId(c) = $nodeId AND elementId(e) = $evacuationCenterId
        MERGE (c)-[:ASSIGNED_TO]->(e)
        `,
        { nodeId, evacuationCenterId: String(relationships.evacuationCenterId), userId }
      );
    }
  }

  if (type === 'hazardZones') {
    const communityIds = idsFrom(relationships.threatensCommunityIds);
    const centerIds = idsFrom(relationships.threatensCenterIds);

    if (replaceExisting && (Object.prototype.hasOwnProperty.call(relationships, 'threatensCommunityIds') || Object.prototype.hasOwnProperty.call(relationships, 'threatensCenterIds'))) {
      await tx.run(
        'MATCH (z:HazardZone) WHERE elementId(z) = $nodeId MATCH (z)-[r:THREATENS]->() DELETE r',
        { nodeId }
      );
    }

    if (communityIds.length) {
      await tx.run(
        `
        MATCH (z:HazardZone) WHERE elementId(z) = $nodeId
        MATCH (c:Community) WHERE elementId(c) IN $communityIds
        MERGE (z)-[:THREATENS]->(c)
        `,
        { nodeId, communityIds, userId }
      );
    }

    if (centerIds.length) {
      await tx.run(
        `
        MATCH (z:HazardZone) WHERE elementId(z) = $nodeId
        MATCH (e:EvacuationCenter) WHERE elementId(e) IN $centerIds
        MERGE (z)-[:THREATENS]->(e)
        `,
        { nodeId, centerIds, userId }
      );
    }
  }

  if (type === 'evacuationCenters') {
    if (replaceExisting && Object.prototype.hasOwnProperty.call(relationships, 'resourceIds')) {
      await tx.run(
        'MATCH (e:EvacuationCenter) WHERE elementId(e) = $nodeId MATCH (e)-[r:HAS_STOCK]->(:Resource) DELETE r',
        { nodeId }
      );
    }

    const resourceIds = idsFrom(relationships.resourceIds);
    if (resourceIds.length) {
      await tx.run(
        `
        MATCH (e:EvacuationCenter) WHERE elementId(e) = $nodeId
        MATCH (r:Resource) WHERE elementId(r) IN $resourceIds
        MERGE (e)-[:HAS_STOCK]->(r)
        `,
        { nodeId, resourceIds, userId }
      );
    }
  }

  if (type === 'resources') {
    if (replaceExisting && Object.prototype.hasOwnProperty.call(relationships, 'evacuationCenterId')) {
      await tx.run(
        'MATCH (:EvacuationCenter)-[rel:HAS_STOCK]->(r:Resource) WHERE elementId(r) = $nodeId DELETE rel',
        { nodeId }
      );
    }

    if (relationships.evacuationCenterId) {
      await tx.run(
        `
        MATCH (e:EvacuationCenter)
        MATCH (r:Resource)
        WHERE elementId(e) = $evacuationCenterId AND elementId(r) = $nodeId
        MERGE (e)-[:HAS_STOCK]->(r)
        `,
        { nodeId, evacuationCenterId: String(relationships.evacuationCenterId), userId }
      );
    }
  }

  if (type === 'incidentReports') {
    if (replaceExisting && Object.prototype.hasOwnProperty.call(relationships, 'communityId')) {
      await tx.run(
        'MATCH (i:IncidentReport) WHERE elementId(i) = $nodeId MATCH (i)-[r:AFFECTS]->(:Community) DELETE r',
        { nodeId }
      );
    }

    if (relationships.communityId) {
      await tx.run(
        `
        MATCH (i:IncidentReport)
        MATCH (c:Community)
        WHERE elementId(i) = $nodeId AND elementId(c) = $communityId
        MERGE (i)-[:AFFECTS]->(c)
        `,
        { nodeId, communityId: String(relationships.communityId), userId }
      );
    }
  }

  if (type === 'preparednessItems') {
    if (replaceExisting && Object.prototype.hasOwnProperty.call(relationships, 'targetId')) {
      await tx.run(
        'MATCH (p:PreparednessItem) WHERE elementId(p) = $nodeId MATCH (p)-[r:CHECKS]->() DELETE r',
        { nodeId }
      );
    }

    if (relationships.targetId) {
      await tx.run(
        `
        MATCH (p:PreparednessItem)
        MATCH (target)
        WHERE elementId(p) = $nodeId
          AND elementId(target) = $targetId
          AND any(label IN labels(target) WHERE label IN ['Community', 'EvacuationCenter'])
        MERGE (p)-[:CHECKS]->(target)
        `,
        { nodeId, targetId: String(relationships.targetId), userId }
      );
    }
  }
}

async function requireAuth(req, res, next) {
  const session = getSession(neo4j.session.READ);

  try {
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    if (!token) {
      return res.status(401).json({ error: 'Please log in first' });
    }

    const result = await session.run(
      `
      MATCH (u:AppUser)-[:HAS_SESSION]->(s:AppSession {token: $token})
      WHERE datetime(s.expiresAt) > datetime()
      RETURN u
      LIMIT 1
      `,
      { token }
    );

    if (!result.records.length) {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }

    req.user = userToJson(result.records[0].get('u'));
    next();
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ error: 'Admin access is required for this action' });
  }
  next();
}

router.post('/auth/register', async (req, res, next) => {
  const session = getSession();

  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const { salt, passwordHash } = hashPassword(password);
    const userId = crypto.randomUUID();
    const now = new Date().toISOString();
    const token = createSessionToken();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();
    const role = ADMIN_EMAIL && email === ADMIN_EMAIL ? 'admin' : 'user';

    const result = await session.executeWrite(async (tx) => {
      const existing = await tx.run(
        'MATCH (u:AppUser {email: $email}) RETURN u LIMIT 1',
        { email }
      );

      if (existing.records.length) {
        const error = new Error('An account with this email already exists');
        error.status = 409;
        throw error;
      }

      const created = await tx.run(
        `
        CREATE (u:AppUser {
          id: $userId,
          name: $name,
          email: $email,
          passwordHash: $passwordHash,
          salt: $salt,
          role: $role,
          createdAt: $now
        })
        CREATE (s:AppSession {
          token: $token,
          createdAt: $now,
          expiresAt: $expiresAt
        })
        CREATE (u)-[:HAS_SESSION]->(s)
        RETURN u
        `,
        { userId, name, email, passwordHash, salt, role, now, token, expiresAt }
      );

      return created.records[0].get('u');
    });

    res.status(201).json({ token, user: userToJson(result) });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.post('/auth/login', async (req, res, next) => {
  const session = getSession();

  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const token = createSessionToken();
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

    const user = await session.executeWrite(async (tx) => {
      const result = await tx.run(
        'MATCH (u:AppUser {email: $email}) RETURN u LIMIT 1',
        { email }
      );

      if (!result.records.length) {
        const error = new Error('Invalid email or password');
        error.status = 401;
        throw error;
      }

      const userNode = result.records[0].get('u');
      const props = toNative(userNode.properties);

      if (!verifyPassword(password, props.salt, props.passwordHash)) {
        const error = new Error('Invalid email or password');
        error.status = 401;
        throw error;
      }

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        SET u.role = CASE WHEN $isAdminEmail THEN 'admin' ELSE coalesce(u.role, 'user') END
        CREATE (s:AppSession {
          token: $token,
          createdAt: $now,
          expiresAt: $expiresAt
        })
        CREATE (u)-[:HAS_SESSION]->(s)
        `,
        { userId: props.id, isAdminEmail: Boolean(ADMIN_EMAIL && email === ADMIN_EMAIL), token, now, expiresAt }
      );

      const refreshed = await tx.run(
        'MATCH (u:AppUser {id: $userId}) RETURN u',
        { userId: props.id }
      );

      return refreshed.records[0].get('u');
    });

    res.json({ token, user: userToJson(user) });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/auth/me', async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    if (!token) {
      return res.status(401).json({ error: 'Missing session token' });
    }

    const result = await session.run(
      `
      MATCH (u:AppUser)-[:HAS_SESSION]->(s:AppSession {token: $token})
      WHERE datetime(s.expiresAt) > datetime()
      RETURN u
      LIMIT 1
      `,
      { token }
    );

    if (!result.records.length) {
      return res.status(401).json({ error: 'Session expired or invalid' });
    }

    res.json({ user: userToJson(result.records[0].get('u')) });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.post('/auth/logout', async (req, res, next) => {
  const session = getSession();

  try {
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    if (token) {
      await session.run(
        'MATCH (:AppUser)-[r:HAS_SESSION]->(s:AppSession {token: $token}) DELETE r, s',
        { token }
      );
    }

    res.status(204).send();
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/health', async (_req, res, next) => {
  try {
    await verifyConnection();
    res.json({ status: 'ok', database: 'connected' });
  } catch (error) {
    next(error);
  }
});

router.use(requireAuth);

router.get('/nodes/:type', async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const { label } = getNodeConfig(req.params.type);
    const result = await session.run(
      `
      MATCH (n:${label})
      OPTIONAL MATCH (n)-[out]->(target)
      OPTIONAL MATCH (source)-[inRel]->(n)
      RETURN n,
             collect(DISTINCT {
               id: elementId(out),
               type: type(out),
               target: elementId(target),
               targetLabel: labels(target)[0],
               targetName: coalesce(target.name, target.type, labels(target)[0])
             }) AS outgoing,
             collect(DISTINCT {
               id: elementId(inRel),
               type: type(inRel),
               source: elementId(source),
               sourceLabel: labels(source)[0],
               sourceName: coalesce(source.name, source.type, labels(source)[0])
             }) AS incoming
      ORDER BY coalesce(n.name, n.type)
      `
    );

    res.json(result.records.map((record) => ({
      ...nodeToJson(record.get('n')),
      outgoing: toNative(record.get('outgoing')).filter((rel) => rel.id),
      incoming: toNative(record.get('incoming')).filter((rel) => rel.id)
    })));
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/my-nodes', async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const result = await session.run(
      `
      MATCH (:AppUser {id: $userId})-[:OWNS]->(n)
      WHERE any(label IN labels(n) WHERE label IN $labels)
      OPTIONAL MATCH (n)-[out]->(target)
      OPTIONAL MATCH (source)-[inRel]->(n)
      RETURN n,
             collect(DISTINCT {
               id: elementId(out),
               type: type(out),
               target: elementId(target),
               targetLabel: labels(target)[0],
               targetName: coalesce(target.name, target.type, labels(target)[0])
             }) AS outgoing,
             collect(DISTINCT {
               id: elementId(inRel),
               type: type(inRel),
               source: elementId(source),
               sourceLabel: labels(source)[0],
               sourceName: coalesce(source.name, source.type, labels(source)[0])
             }) AS incoming
      ORDER BY labels(n)[0], coalesce(n.name, n.title, n.type)
      `,
      { userId: req.user.id, labels: APP_LABELS }
    );

    res.json(result.records.map((record) => ({
      ...nodeToJson(record.get('n')),
      outgoing: toNative(record.get('outgoing')).filter((rel) => rel.id),
      incoming: toNative(record.get('incoming')).filter((rel) => rel.id)
    })));
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.post('/nodes/:type', async (req, res, next) => {
  const session = getSession();

  try {
    const type = req.params.type;
    const { label } = getNodeConfig(type);
    const properties = normalizeProperties(type, req.body.properties);
    const relationships = req.body.relationships || {};

    const createdNode = await session.executeWrite(async (tx) => {
      const result = await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        CREATE (u)-[:OWNS]->(n:${label})
        SET n = $properties
        RETURN n
        `,
        { properties, userId: req.user.id }
      );
      const node = result.records[0].get('n');
      await applyRelationships(tx, type, node.elementId, { ...relationships, userId: req.user.id }, true);
      await writeAudit(tx, req.user.id, 'Created', label, properties.name || properties.title || properties.type);
      const refreshed = await tx.run(
        `MATCH (:AppUser {id: $userId})-[:OWNS]->(n:${label}) WHERE elementId(n) = $nodeId RETURN n`,
        { nodeId: node.elementId, userId: req.user.id }
      );
      return refreshed.records[0].get('n');
    });

    res.status(201).json(nodeToJson(createdNode));
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.patch('/nodes/:type/:id', async (req, res, next) => {
  const session = getSession();

  try {
    const type = req.params.type;
    const { label } = getNodeConfig(type);
    const properties = normalizeProperties(type, req.body.properties);
    const relationships = req.body.relationships || {};

    const updatedNode = await session.executeWrite(async (tx) => {
      const result = await tx.run(
        `
        MATCH (n:${label})
        WHERE elementId(n) = $id
        OPTIONAL MATCH (owner:AppUser)-[:OWNS]->(n)
        WITH n, collect(owner.id) AS ownerIds
        WHERE $isAdmin OR $userId IN ownerIds
        SET n += $properties
        RETURN n
        `,
        { id: req.params.id, properties, userId: req.user.id, isAdmin: req.user.isAdmin }
      );

      if (!result.records.length) {
        const error = new Error(req.user.isAdmin ? `${label} not found` : `You can only edit ${label} records you added`);
        error.status = req.user.isAdmin ? 404 : 403;
        throw error;
      }

      await applyRelationships(tx, type, req.params.id, { ...relationships, userId: req.user.id }, true);
      await writeAudit(tx, req.user.id, 'Updated', label, properties.name || properties.title || properties.type);
      const refreshed = await tx.run(
        `MATCH (n:${label}) WHERE elementId(n) = $id RETURN n`,
        { id: req.params.id }
      );
      return refreshed.records[0].get('n');
    });

    res.json(nodeToJson(updatedNode));
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.delete('/nodes/:type/:id', requireAdmin, async (req, res, next) => {
  const session = getSession();

  try {
    const { label } = getNodeConfig(req.params.type);

    const deletedCount = await session.executeWrite(async (tx) => {
      const result = await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        MATCH (n:${label})
        WHERE elementId(n) = $id
        WITH u, n, count(n) AS deleted, coalesce(n.name, n.title, n.type, labels(n)[0]) AS entityName
        CREATE (u)-[:OWNS]->(:AuditLog {
          action: 'Deleted',
          entityType: $label,
          entityName: entityName,
          createdAt: datetime()
        })
        DETACH DELETE n
        RETURN deleted
        `,
        { id: req.params.id, userId: req.user.id, label }
      );
      return result.records[0].get('deleted').toNumber();
    });

    if (!deletedCount) {
      return res.status(404).json({ error: `${label} not found` });
    }

    return res.status(204).send();
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/search/community', async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const name = String(req.query.name || '').trim();
    if (!name) {
      return res.status(400).json({ error: 'Community name is required' });
    }

    const result = await session.run(
      `
      MATCH (c:Community)
      WHERE toLower(c.name) = toLower($name)
         OR toLower(c.name) CONTAINS toLower($name)
      OPTIONAL MATCH (c)-[:ASSIGNED_TO]->(center:EvacuationCenter)
      OPTIONAL MATCH (center)-[:HAS_STOCK]->(resource:Resource)
      OPTIONAL MATCH (c)-[:LOCATED_IN]->(zone:HazardZone)
      OPTIONAL MATCH (zone)-[:THREATENS]->(threat)
      RETURN c,
             center,
             collect(DISTINCT resource) AS resources,
             collect(DISTINCT zone) AS hazardZones,
             collect(DISTINCT threat) AS threatenedTargets
      ORDER BY c.name
      LIMIT 1
      `,
      { name }
    );

    if (!result.records.length) {
      return res.status(404).json({ error: 'Community not found' });
    }

    const record = result.records[0];
    return res.json({
      community: nodeToJson(record.get('c')),
      evacuationCenter: nodeToJson(record.get('center')),
      resources: record.get('resources').filter(Boolean).map(nodeToJson),
      hazardZones: record.get('hazardZones').filter(Boolean).map(nodeToJson),
      threatenedTargets: record.get('threatenedTargets').filter(Boolean).map(nodeToJson)
    });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/dashboard', async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const countsResult = await session.run(
      `
      MATCH (n)
      WHERE any(label IN labels(n) WHERE label IN $labels)
      UNWIND labels(n) AS label
      WITH label, count(*) AS count
      WHERE label IN $labels
      RETURN label, count
      `,
      { labels: APP_LABELS }
    );

    const counts = {
      Community: 0,
      HazardZone: 0,
      EvacuationCenter: 0,
      Resource: 0,
      IncidentReport: 0,
      PreparednessItem: 0
    };

    countsResult.records.forEach((record) => {
      counts[record.get('label')] = record.get('count').toNumber();
    });

    const capacityResult = await session.run(
      `
      MATCH (center:EvacuationCenter)
      OPTIONAL MATCH (community:Community)-[:ASSIGNED_TO]->(center)
      WITH center, coalesce(sum(community.population), 0) AS assignedPopulation
      RETURN center.name AS name,
             center.capacity AS capacity,
             assignedPopulation,
             CASE
               WHEN center.capacity - assignedPopulation < 0 THEN 0
               ELSE center.capacity - assignedPopulation
             END AS remainingCapacity
      ORDER BY name
      `,
      {}
    );

    const evacuationCapacity = capacityResult.records.map((record) => ({
      name: record.get('name') || 'Unnamed center',
      capacity: toNative(record.get('capacity')) || 0,
      assignedPopulation: toNative(record.get('assignedPopulation')) || 0,
      remainingCapacity: toNative(record.get('remainingCapacity')) || 0
    }));

    const priorityResult = await session.run(
      `
      MATCH (community:Community)
      OPTIONAL MATCH (community)-[:LOCATED_IN]->(zone:HazardZone)
      OPTIONAL MATCH (community)-[:ASSIGNED_TO]->(center:EvacuationCenter)
      OPTIONAL MATCH (other:Community)-[:ASSIGNED_TO]->(center)
      WITH community, zone, center, coalesce(sum(other.population), 0) AS assignedPopulation
      WITH community, zone, center, assignedPopulation,
           CASE community.vulnerabilityLevel
             WHEN 'Critical' THEN 40
             WHEN 'High' THEN 30
             WHEN 'Moderate' THEN 20
             ELSE 10
           END AS vulnerabilityScore,
           CASE zone.riskLevel
             WHEN 'Critical' THEN 35
             WHEN 'High' THEN 25
             WHEN 'Moderate' THEN 15
             ELSE 5
           END AS hazardScore,
           CASE
             WHEN community.population >= 4000 THEN 15
             WHEN community.population >= 2500 THEN 10
             ELSE 5
           END AS populationScore,
           CASE
             WHEN center IS NULL THEN 10
             WHEN center.capacity <= assignedPopulation THEN 10
             WHEN center.capacity - assignedPopulation < 200 THEN 5
             ELSE 0
           END AS capacityScore
      RETURN community.name AS community,
             coalesce(zone.name, zone.type, 'No hazard zone') AS hazardZone,
             coalesce(center.name, 'No evacuation center') AS evacuationCenter,
             vulnerabilityScore + hazardScore + populationScore + capacityScore AS score
      ORDER BY score DESC, community.name
      LIMIT 8
      `,
      {}
    );

    const priorities = priorityResult.records.map((record) => ({
      community: record.get('community'),
      hazardZone: record.get('hazardZone'),
      evacuationCenter: record.get('evacuationCenter'),
      score: toNative(record.get('score')) || 0
    }));

    const alertsResult = await session.run(
      `
      MATCH (center:EvacuationCenter)
      OPTIONAL MATCH (community:Community)-[:ASSIGNED_TO]->(center)
      WITH center, coalesce(sum(community.population), 0) AS assignedPopulation
      WHERE center.capacity <= assignedPopulation OR center.status IN ['Full', 'Closed', 'Maintenance']
      RETURN 'Capacity' AS category,
             center.name AS title,
             CASE
               WHEN center.capacity <= assignedPopulation THEN 'Assigned population exceeds or equals capacity'
               ELSE 'Center status needs attention: ' + center.status
             END AS message
      UNION
      MATCH (center:EvacuationCenter)-[:HAS_STOCK]->(resource:Resource)
      WHERE resource.quantity < CASE resource.type
        WHEN 'Water' THEN 1500
        WHEN 'Food' THEN 1200
        ELSE 500
      END
      RETURN 'Resource' AS category,
             center.name AS title,
             resource.type + ' stock is below recommended level (' + toString(resource.quantity) + ')' AS message
      ORDER BY category, title
      LIMIT 12
      `,
      {}
    );

    const alerts = alertsResult.records.map((record) => ({
      category: record.get('category'),
      title: record.get('title'),
      message: record.get('message')
    }));

    res.json({ counts, evacuationCapacity, priorities, alerts });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/backup', requireAdmin, async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const nodesResult = await session.run(
      `
      MATCH (n)
      WHERE any(label IN labels(n) WHERE label IN $labels)
      RETURN n
      ORDER BY labels(n)[0], coalesce(n.name, n.type)
      `,
      { labels: APP_LABELS }
    );

    const relationshipsResult = await session.run(
      `
      MATCH (a)-[r]->(b)
      WHERE any(label IN labels(a) WHERE label IN $labels)
        AND any(label IN labels(b) WHERE label IN $labels)
      RETURN r
      ORDER BY type(r)
      `,
      { labels: APP_LABELS }
    );

    const backup = {
      exportedAt: new Date().toISOString(),
      graph: {
        nodes: nodesResult.records.map((record) => nodeToJson(record.get('n'))),
        relationships: relationshipsResult.records.map((record) => relationshipToJson(record.get('r')))
      }
    };

    const filename = `drrca-graph-backup-${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(JSON.stringify(backup, null, 2));
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.post('/restore', requireAdmin, async (req, res, next) => {
  const session = getSession();

  try {
    const graph = req.body?.graph || {};
    const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
    const relationships = Array.isArray(graph.relationships) ? graph.relationships : [];
    const allowedLabels = new Set(APP_LABELS);
    const allowedRelationships = new Set(['LOCATED_IN', 'ASSIGNED_TO', 'HAS_STOCK', 'THREATENS', 'AFFECTS', 'CHECKS']);

    const cleanNodes = nodes
      .filter((node) => allowedLabels.has(node.label))
      .map((node) => ({
        importId: String(node.id),
        label: node.label,
        properties: toNative(node.properties || {})
      }));

    const cleanRelationships = relationships
      .filter((relationship) => allowedRelationships.has(relationship.type))
      .map((relationship) => ({
        type: relationship.type,
        startNodeId: String(relationship.startNodeId),
        endNodeId: String(relationship.endNodeId)
      }));

    await session.executeWrite(async (tx) => {
      const importBatchId = crypto.randomUUID();

      for (const node of cleanNodes) {
        const properties = {
          ...node.properties,
          ownerId: req.user.id,
          importId: node.importId,
          importBatchId
        };

        await tx.run(
          `
          MATCH (u:AppUser {id: $userId})
          CREATE (u)-[:OWNS]->(n:${node.label})
          SET n = $properties
          `,
          { userId: req.user.id, properties }
        );
      }

      for (const relationship of cleanRelationships) {
        await tx.run(
          `
          MATCH (:AppUser {id: $userId})-[:OWNS]->(a {importBatchId: $importBatchId, importId: $startNodeId})
          MATCH (:AppUser {id: $userId})-[:OWNS]->(b {importBatchId: $importBatchId, importId: $endNodeId})
          MERGE (a)-[:${relationship.type}]->(b)
          `,
          {
            userId: req.user.id,
            importBatchId,
            startNodeId: relationship.startNodeId,
            endNodeId: relationship.endNodeId
          }
        );
      }

      await writeAudit(tx, req.user.id, 'Restored Backup', 'Graph', `${cleanNodes.length} nodes`);
    });

    res.status(201).json({
      message: 'Backup restored',
      nodes: cleanNodes.length,
      relationships: cleanRelationships.length
    });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/graph', async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const result = await session.run(
      `
      MATCH (n)
      WHERE any(label IN labels(n) WHERE label IN $labels)
      OPTIONAL MATCH (n)-[r]->(m)
      WHERE any(label IN labels(m) WHERE label IN $labels)
      RETURN collect(DISTINCT n) AS nodes, collect(DISTINCT r) AS relationships
      `,
      { labels: APP_LABELS }
    );

    const record = result.records[0];
    res.json({
      nodes: record.get('nodes').filter(Boolean).map(nodeToJson),
      relationships: record.get('relationships').filter(Boolean).map(relationshipToJson)
    });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/audit-logs', requireAdmin, async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const result = await session.run(
      `
      MATCH (log:AuditLog)
      RETURN log
      ORDER BY log.createdAt DESC
      LIMIT 20
      `,
      {}
    );

    res.json(result.records.map((record) => nodeToJson(record.get('log'))));
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.post('/seed-samples', requireAdmin, async (req, res, next) => {
  const session = getSession();

  const hazardZones = [
    { sampleId: 'sample-zone-1', index: 1, name: 'Mandulog River Floodplain', type: 'Flood', riskLevel: 'Critical' },
    { sampleId: 'sample-zone-2', index: 2, name: 'Hinaplanon Low-Lying Area', type: 'Flood', riskLevel: 'High' },
    { sampleId: 'sample-zone-3', index: 3, name: 'Tibanga Creek Overflow Zone', type: 'Flood', riskLevel: 'High' },
    { sampleId: 'sample-zone-4', index: 4, name: 'Pala-o Urban Drainage Basin', type: 'Flood', riskLevel: 'Moderate' },
    { sampleId: 'sample-zone-5', index: 5, name: 'Tambacan Riverside Area', type: 'Flood', riskLevel: 'Critical' },
    { sampleId: 'sample-zone-6', index: 6, name: 'Maria Cristina Slope Area', type: 'Landslide', riskLevel: 'High' },
    { sampleId: 'sample-zone-7', index: 7, name: 'Buru-un Hillside Area', type: 'Landslide', riskLevel: 'High' },
    { sampleId: 'sample-zone-8', index: 8, name: 'Dalipuga Coastal Flood Zone', type: 'Flood', riskLevel: 'Moderate' },
    { sampleId: 'sample-zone-9', index: 9, name: 'Upper Luinab Slope Area', type: 'Landslide', riskLevel: 'High' },
    { sampleId: 'sample-zone-10', index: 10, name: 'Kiwalan Shoreline Flood Zone', type: 'Flood', riskLevel: 'Critical' }
  ];

  const evacuationCenters = [
    { sampleId: 'sample-center-1', index: 1, name: 'Iligan City National High School Evacuation Center', capacity: 2200, status: 'Open' },
    { sampleId: 'sample-center-2', index: 2, name: 'Hinaplanon Barangay Gym Shelter', capacity: 900, status: 'Open' },
    { sampleId: 'sample-center-3', index: 3, name: 'MSU-IIT Gymnasium Relief Center', capacity: 1600, status: 'Open' },
    { sampleId: 'sample-center-4', index: 4, name: 'Pala-o Barangay Hall Evacuation Site', capacity: 800, status: 'Maintenance' },
    { sampleId: 'sample-center-5', index: 5, name: 'Tambacan Elementary School Shelter', capacity: 750, status: 'Open' },
    { sampleId: 'sample-center-6', index: 6, name: 'Maria Cristina Barangay Gym', capacity: 1100, status: 'Open' },
    { sampleId: 'sample-center-7', index: 7, name: 'Buru-un Covered Court Evacuation Center', capacity: 950, status: 'Full' },
    { sampleId: 'sample-center-8', index: 8, name: 'Dalipuga National High School Shelter', capacity: 1200, status: 'Open' },
    { sampleId: 'sample-center-9', index: 9, name: 'Luinab Multipurpose Hall', capacity: 700, status: 'Open' },
    { sampleId: 'sample-center-10', index: 10, name: 'Kiwalan Elementary School Evacuation Site', capacity: 850, status: 'Open' }
  ];

  const resources = [
    { sampleId: 'sample-resource-1', centerId: 'sample-center-1', type: 'Water', quantity: 3500 },
    { sampleId: 'sample-resource-2', centerId: 'sample-center-2', type: 'Medical', quantity: 420 },
    { sampleId: 'sample-resource-3', centerId: 'sample-center-3', type: 'Food', quantity: 2400 },
    { sampleId: 'sample-resource-4', centerId: 'sample-center-4', type: 'Water', quantity: 1800 },
    { sampleId: 'sample-resource-5', centerId: 'sample-center-5', type: 'Food', quantity: 1900 },
    { sampleId: 'sample-resource-6', centerId: 'sample-center-6', type: 'Medical', quantity: 650 },
    { sampleId: 'sample-resource-7', centerId: 'sample-center-7', type: 'Water', quantity: 1400 },
    { sampleId: 'sample-resource-8', centerId: 'sample-center-8', type: 'Food', quantity: 1700 },
    { sampleId: 'sample-resource-9', centerId: 'sample-center-9', type: 'Medical', quantity: 380 },
    { sampleId: 'sample-resource-10', centerId: 'sample-center-10', type: 'Water', quantity: 2100 }
  ];

  const communities = [
    { sampleId: 'sample-community-1', zoneId: 'sample-zone-1', centerId: 'sample-center-1', name: 'Barangay Mandulog, Iligan City', population: 4600, vulnerabilityLevel: 'Critical' },
    { sampleId: 'sample-community-2', zoneId: 'sample-zone-2', centerId: 'sample-center-2', name: 'Barangay Hinaplanon, Iligan City', population: 3200, vulnerabilityLevel: 'High' },
    { sampleId: 'sample-community-3', zoneId: 'sample-zone-3', centerId: 'sample-center-3', name: 'Barangay Tibanga, Iligan City', population: 2800, vulnerabilityLevel: 'High' },
    { sampleId: 'sample-community-4', zoneId: 'sample-zone-4', centerId: 'sample-center-4', name: 'Barangay Pala-o, Iligan City', population: 2400, vulnerabilityLevel: 'Moderate' },
    { sampleId: 'sample-community-5', zoneId: 'sample-zone-5', centerId: 'sample-center-5', name: 'Barangay Tambacan, Iligan City', population: 2100, vulnerabilityLevel: 'Critical' },
    { sampleId: 'sample-community-6', zoneId: 'sample-zone-6', centerId: 'sample-center-6', name: 'Barangay Maria Cristina, Iligan City', population: 3900, vulnerabilityLevel: 'High' },
    { sampleId: 'sample-community-7', zoneId: 'sample-zone-7', centerId: 'sample-center-7', name: 'Barangay Buru-un, Iligan City', population: 3500, vulnerabilityLevel: 'High' },
    { sampleId: 'sample-community-8', zoneId: 'sample-zone-8', centerId: 'sample-center-8', name: 'Barangay Dalipuga, Iligan City', population: 2700, vulnerabilityLevel: 'Moderate' },
    { sampleId: 'sample-community-9', zoneId: 'sample-zone-9', centerId: 'sample-center-9', name: 'Barangay Luinab, Iligan City', population: 1800, vulnerabilityLevel: 'High' },
    { sampleId: 'sample-community-10', zoneId: 'sample-zone-10', centerId: 'sample-center-10', name: 'Barangay Kiwalan, Iligan City', population: 2300, vulnerabilityLevel: 'Critical' }
  ];

  const incidentReports = [
    { sampleId: 'sample-incident-1', communityId: 'sample-community-1', title: 'Mandulog River Water Level Rising', severity: 'Critical', description: 'Rapid water level increase reported near low-lying homes.', reportedAt: '2026-06-26T08:00:00.000Z' },
    { sampleId: 'sample-incident-2', communityId: 'sample-community-5', title: 'Tambacan Drainage Overflow', severity: 'High', description: 'Street flooding affecting access to evacuation route.', reportedAt: '2026-06-26T08:20:00.000Z' },
    { sampleId: 'sample-incident-3', communityId: 'sample-community-6', title: 'Maria Cristina Slope Monitoring Alert', severity: 'High', description: 'Soil movement warning from hillside watch volunteers.', reportedAt: '2026-06-26T08:40:00.000Z' }
  ];

  const preparednessItems = [
    { sampleId: 'sample-check-1', targetId: 'sample-community-1', title: 'Early warning siren tested', status: 'Done', notes: 'Barangay responders confirmed siren test.' },
    { sampleId: 'sample-check-2', targetId: 'sample-community-2', title: 'Transport plan verified', status: 'In Progress', notes: 'Two vehicles assigned, one pending confirmation.' },
    { sampleId: 'sample-check-3', targetId: 'sample-center-3', title: 'Medical station ready', status: 'Done', notes: 'Basic triage area prepared.' },
    { sampleId: 'sample-check-4', targetId: 'sample-center-7', title: 'Backup water source confirmed', status: 'Pending', notes: 'Needs coordination with water district.' }
  ];

  try {
    await session.executeWrite(async (tx) => {
      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $hazardZones AS row
        MERGE (z:HazardZone {ownerId: $userId, sampleId: row.sampleId})
        SET z.name = row.name,
            z.type = row.type,
            z.riskLevel = row.riskLevel,
            z.sampleIndex = row.index
        MERGE (u)-[:OWNS]->(z)
        `,
        { hazardZones, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $evacuationCenters AS row
        MERGE (e:EvacuationCenter {ownerId: $userId, sampleId: row.sampleId})
        SET e.name = row.name,
            e.capacity = row.capacity,
            e.status = row.status,
            e.sampleIndex = row.index
        MERGE (u)-[:OWNS]->(e)
        `,
        { evacuationCenters, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $resources AS row
        MERGE (r:Resource {ownerId: $userId, sampleId: row.sampleId})
        SET r.type = row.type,
            r.quantity = row.quantity
        MERGE (u)-[:OWNS]->(r)
        WITH row, r
        MATCH (e:EvacuationCenter {ownerId: $userId, sampleId: row.centerId})
        MERGE (e)-[:HAS_STOCK]->(r)
        `,
        { resources, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $communities AS row
        MERGE (c:Community {ownerId: $userId, sampleId: row.sampleId})
        SET c.name = row.name,
            c.population = row.population,
            c.vulnerabilityLevel = row.vulnerabilityLevel
        MERGE (u)-[:OWNS]->(c)
        WITH row, c
        MATCH (z:HazardZone {ownerId: $userId, sampleId: row.zoneId})
        MATCH (e:EvacuationCenter {ownerId: $userId, sampleId: row.centerId})
        MERGE (c)-[:LOCATED_IN]->(z)
        MERGE (c)-[:ASSIGNED_TO]->(e)
        MERGE (z)-[:THREATENS]->(c)
        MERGE (z)-[:THREATENS]->(e)
        `,
        { communities, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $incidentReports AS row
        MERGE (i:IncidentReport {ownerId: $userId, sampleId: row.sampleId})
        SET i.title = row.title,
            i.severity = row.severity,
            i.description = row.description,
            i.reportedAt = row.reportedAt
        MERGE (u)-[:OWNS]->(i)
        WITH row, i
        MATCH (c:Community {ownerId: $userId, sampleId: row.communityId})
        MERGE (i)-[:AFFECTS]->(c)
        `,
        { incidentReports, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $preparednessItems AS row
        MERGE (p:PreparednessItem {ownerId: $userId, sampleId: row.sampleId})
        SET p.title = row.title,
            p.status = row.status,
            p.notes = row.notes
        MERGE (u)-[:OWNS]->(p)
        WITH row, p
        MATCH (target {ownerId: $userId, sampleId: row.targetId})
        MERGE (p)-[:CHECKS]->(target)
        `,
        { preparednessItems, userId: req.user.id }
      );

      await writeAudit(tx, req.user.id, 'Seeded Samples', 'Graph', 'Iligan DRRCA sample set');
    });

    res.status(201).json({
      message: 'Sample graph data created',
      counts: {
        communities: communities.length,
        hazardZones: hazardZones.length,
        evacuationCenters: evacuationCenters.length,
        resources: resources.length,
        incidentReports: incidentReports.length,
        preparednessItems: preparednessItems.length
      }
    });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.post('/seed-samples-2', requireAdmin, async (req, res, next) => {
  const session = getSession();

  const hazardZones = [
    { sampleId: 'sample2-zone-1', index: 1, name: 'Santiago Coastal Flood Area', type: 'Flood', riskLevel: 'High' },
    { sampleId: 'sample2-zone-2', index: 2, name: 'San Miguel Urban Flood Basin', type: 'Flood', riskLevel: 'Moderate' },
    { sampleId: 'sample2-zone-3', index: 3, name: 'Tipanoy Creek Overflow Area', type: 'Flood', riskLevel: 'High' },
    { sampleId: 'sample2-zone-4', index: 4, name: 'Digkilaan Upland Slope Area', type: 'Landslide', riskLevel: 'Critical' },
    { sampleId: 'sample2-zone-5', index: 5, name: 'Rogongon Mountain Road Slope', type: 'Landslide', riskLevel: 'Critical' },
    { sampleId: 'sample2-zone-6', index: 6, name: 'Panoroganan Ridge Settlement Area', type: 'Landslide', riskLevel: 'High' },
    { sampleId: 'sample2-zone-7', index: 7, name: 'Abuno Riverbank Floodplain', type: 'Flood', riskLevel: 'Moderate' },
    { sampleId: 'sample2-zone-8', index: 8, name: 'Suarez Drainage Catchment', type: 'Flood', riskLevel: 'High' },
    { sampleId: 'sample2-zone-9', index: 9, name: 'Sta. Filomena Low-Lying Area', type: 'Flood', riskLevel: 'Moderate' },
    { sampleId: 'sample2-zone-10', index: 10, name: 'Tominobo Hillside Area', type: 'Landslide', riskLevel: 'High' }
  ];

  const evacuationCenters = [
    { sampleId: 'sample2-center-1', index: 1, name: 'Santiago Barangay Gym Evacuation Center', capacity: 950, status: 'Open' },
    { sampleId: 'sample2-center-2', index: 2, name: 'San Miguel Central School Shelter', capacity: 1100, status: 'Open' },
    { sampleId: 'sample2-center-3', index: 3, name: 'Tipanoy Covered Court', capacity: 780, status: 'Open' },
    { sampleId: 'sample2-center-4', index: 4, name: 'Digkilaan Multipurpose Hall', capacity: 650, status: 'Maintenance' },
    { sampleId: 'sample2-center-5', index: 5, name: 'Rogongon Tribal Hall Shelter', capacity: 500, status: 'Open' },
    { sampleId: 'sample2-center-6', index: 6, name: 'Panoroganan Elementary School Shelter', capacity: 600, status: 'Open' },
    { sampleId: 'sample2-center-7', index: 7, name: 'Abuno High School Evacuation Site', capacity: 900, status: 'Open' },
    { sampleId: 'sample2-center-8', index: 8, name: 'Suarez Barangay Hall Relief Center', capacity: 700, status: 'Full' },
    { sampleId: 'sample2-center-9', index: 9, name: 'Sta. Filomena Parish Hall Shelter', capacity: 850, status: 'Open' },
    { sampleId: 'sample2-center-10', index: 10, name: 'Tominobo Covered Court', capacity: 720, status: 'Open' }
  ];

  const resources = [
    { sampleId: 'sample2-resource-1', centerId: 'sample2-center-1', type: 'Food', quantity: 1250 },
    { sampleId: 'sample2-resource-2', centerId: 'sample2-center-2', type: 'Water', quantity: 2600 },
    { sampleId: 'sample2-resource-3', centerId: 'sample2-center-3', type: 'Medical', quantity: 320 },
    { sampleId: 'sample2-resource-4', centerId: 'sample2-center-4', type: 'Food', quantity: 900 },
    { sampleId: 'sample2-resource-5', centerId: 'sample2-center-5', type: 'Water', quantity: 1100 },
    { sampleId: 'sample2-resource-6', centerId: 'sample2-center-6', type: 'Medical', quantity: 520 },
    { sampleId: 'sample2-resource-7', centerId: 'sample2-center-7', type: 'Food', quantity: 1600 },
    { sampleId: 'sample2-resource-8', centerId: 'sample2-center-8', type: 'Water', quantity: 980 },
    { sampleId: 'sample2-resource-9', centerId: 'sample2-center-9', type: 'Medical', quantity: 610 },
    { sampleId: 'sample2-resource-10', centerId: 'sample2-center-10', type: 'Food', quantity: 1350 }
  ];

  const communities = [
    { sampleId: 'sample2-community-1', zoneId: 'sample2-zone-1', centerId: 'sample2-center-1', name: 'Barangay Santiago, Iligan City', population: 2100, vulnerabilityLevel: 'High' },
    { sampleId: 'sample2-community-2', zoneId: 'sample2-zone-2', centerId: 'sample2-center-2', name: 'Barangay San Miguel, Iligan City', population: 2600, vulnerabilityLevel: 'Moderate' },
    { sampleId: 'sample2-community-3', zoneId: 'sample2-zone-3', centerId: 'sample2-center-3', name: 'Barangay Tipanoy, Iligan City', population: 1900, vulnerabilityLevel: 'High' },
    { sampleId: 'sample2-community-4', zoneId: 'sample2-zone-4', centerId: 'sample2-center-4', name: 'Barangay Digkilaan, Iligan City', population: 1400, vulnerabilityLevel: 'Critical' },
    { sampleId: 'sample2-community-5', zoneId: 'sample2-zone-5', centerId: 'sample2-center-5', name: 'Barangay Rogongon, Iligan City', population: 1200, vulnerabilityLevel: 'Critical' },
    { sampleId: 'sample2-community-6', zoneId: 'sample2-zone-6', centerId: 'sample2-center-6', name: 'Barangay Panoroganan, Iligan City', population: 1500, vulnerabilityLevel: 'High' },
    { sampleId: 'sample2-community-7', zoneId: 'sample2-zone-7', centerId: 'sample2-center-7', name: 'Barangay Abuno, Iligan City', population: 2300, vulnerabilityLevel: 'Moderate' },
    { sampleId: 'sample2-community-8', zoneId: 'sample2-zone-8', centerId: 'sample2-center-8', name: 'Barangay Suarez, Iligan City', population: 3100, vulnerabilityLevel: 'High' },
    { sampleId: 'sample2-community-9', zoneId: 'sample2-zone-9', centerId: 'sample2-center-9', name: 'Barangay Sta. Filomena, Iligan City', population: 2400, vulnerabilityLevel: 'Moderate' },
    { sampleId: 'sample2-community-10', zoneId: 'sample2-zone-10', centerId: 'sample2-center-10', name: 'Barangay Tominobo Proper, Iligan City', population: 2000, vulnerabilityLevel: 'High' }
  ];

  const incidentReports = [
    { sampleId: 'sample2-incident-1', communityId: 'sample2-community-4', title: 'Digkilaan Roadside Slope Crack', severity: 'Critical', description: 'Visible cracks reported along upland access road.', reportedAt: '2026-06-26T09:15:00.000Z' },
    { sampleId: 'sample2-incident-2', communityId: 'sample2-community-8', title: 'Suarez Evacuation Center Crowding', severity: 'High', description: 'Center occupancy has reached full status.', reportedAt: '2026-06-26T09:35:00.000Z' },
    { sampleId: 'sample2-incident-3', communityId: 'sample2-community-5', title: 'Rogongon Landslide Watch', severity: 'Critical', description: 'Community watch team requested slope inspection.', reportedAt: '2026-06-26T10:00:00.000Z' }
  ];

  const preparednessItems = [
    { sampleId: 'sample2-check-1', targetId: 'sample2-community-4', title: 'Road access route checked', status: 'In Progress', notes: 'Alternate route needs clearing.' },
    { sampleId: 'sample2-check-2', targetId: 'sample2-center-8', title: 'Overflow shelter identified', status: 'Pending', notes: 'Coordinate with nearby school shelter.' },
    { sampleId: 'sample2-check-3', targetId: 'sample2-center-2', title: 'Food distribution area marked', status: 'Done', notes: 'Queue lanes prepared.' },
    { sampleId: 'sample2-check-4', targetId: 'sample2-community-5', title: 'Slope warning volunteers assigned', status: 'Done', notes: 'Night watch rotation confirmed.' }
  ];

  try {
    await session.executeWrite(async (tx) => {
      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $hazardZones AS row
        MERGE (z:HazardZone {ownerId: $userId, sampleId: row.sampleId})
        SET z.name = row.name, z.type = row.type, z.riskLevel = row.riskLevel, z.sampleIndex = row.index
        MERGE (u)-[:OWNS]->(z)
        `,
        { hazardZones, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $evacuationCenters AS row
        MERGE (e:EvacuationCenter {ownerId: $userId, sampleId: row.sampleId})
        SET e.name = row.name, e.capacity = row.capacity, e.status = row.status, e.sampleIndex = row.index
        MERGE (u)-[:OWNS]->(e)
        `,
        { evacuationCenters, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $resources AS row
        MERGE (r:Resource {ownerId: $userId, sampleId: row.sampleId})
        SET r.type = row.type, r.quantity = row.quantity
        MERGE (u)-[:OWNS]->(r)
        WITH row, r
        MATCH (e:EvacuationCenter {ownerId: $userId, sampleId: row.centerId})
        MERGE (e)-[:HAS_STOCK]->(r)
        `,
        { resources, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $communities AS row
        MERGE (c:Community {ownerId: $userId, sampleId: row.sampleId})
        SET c.name = row.name, c.population = row.population, c.vulnerabilityLevel = row.vulnerabilityLevel
        MERGE (u)-[:OWNS]->(c)
        WITH row, c
        MATCH (z:HazardZone {ownerId: $userId, sampleId: row.zoneId})
        MATCH (e:EvacuationCenter {ownerId: $userId, sampleId: row.centerId})
        MERGE (c)-[:LOCATED_IN]->(z)
        MERGE (c)-[:ASSIGNED_TO]->(e)
        MERGE (z)-[:THREATENS]->(c)
        MERGE (z)-[:THREATENS]->(e)
        `,
        { communities, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $incidentReports AS row
        MERGE (i:IncidentReport {ownerId: $userId, sampleId: row.sampleId})
        SET i.title = row.title, i.severity = row.severity, i.description = row.description, i.reportedAt = row.reportedAt
        MERGE (u)-[:OWNS]->(i)
        WITH row, i
        MATCH (c:Community {ownerId: $userId, sampleId: row.communityId})
        MERGE (i)-[:AFFECTS]->(c)
        `,
        { incidentReports, userId: req.user.id }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $preparednessItems AS row
        MERGE (p:PreparednessItem {ownerId: $userId, sampleId: row.sampleId})
        SET p.title = row.title, p.status = row.status, p.notes = row.notes
        MERGE (u)-[:OWNS]->(p)
        WITH row, p
        MATCH (target {ownerId: $userId, sampleId: row.targetId})
        MERGE (p)-[:CHECKS]->(target)
        `,
        { preparednessItems, userId: req.user.id }
      );

      await writeAudit(tx, req.user.id, 'Seeded Samples 2', 'Graph', 'Expanded Iligan DRRCA sample set');
    });

    res.status(201).json({
      message: 'Sample graph data set 2 created',
      counts: {
        communities: communities.length,
        hazardZones: hazardZones.length,
        evacuationCenters: evacuationCenters.length,
        resources: resources.length,
        incidentReports: incidentReports.length,
        preparednessItems: preparednessItems.length
      }
    });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.post('/seed-my-samples', async (req, res, next) => {
  const session = getSession();
  const prefix = `user-${req.user.id.slice(0, 8)}`;

  const hazardZones = [
    { sampleId: `${prefix}-zone-1`, name: 'User Sample Riverside Flood Area', type: 'Flood', riskLevel: 'High' },
    { sampleId: `${prefix}-zone-2`, name: 'User Sample Hillside Slope Area', type: 'Landslide', riskLevel: 'Moderate' },
    { sampleId: `${prefix}-zone-3`, name: 'User Sample Creek Overflow Area', type: 'Flood', riskLevel: 'Critical' }
  ];

  const evacuationCenters = [
    { sampleId: `${prefix}-center-1`, name: 'User Sample Barangay Gym', capacity: 600, status: 'Open' },
    { sampleId: `${prefix}-center-2`, name: 'User Sample Elementary School Shelter', capacity: 450, status: 'Open' },
    { sampleId: `${prefix}-center-3`, name: 'User Sample Multipurpose Hall', capacity: 350, status: 'Maintenance' }
  ];

  const resources = [
    { sampleId: `${prefix}-resource-1`, centerId: `${prefix}-center-1`, type: 'Water', quantity: 1200 },
    { sampleId: `${prefix}-resource-2`, centerId: `${prefix}-center-2`, type: 'Food', quantity: 900 },
    { sampleId: `${prefix}-resource-3`, centerId: `${prefix}-center-3`, type: 'Medical', quantity: 250 }
  ];

  const communities = [
    { sampleId: `${prefix}-community-1`, zoneId: `${prefix}-zone-1`, centerId: `${prefix}-center-1`, name: 'User Sample Riverside Community', population: 900, vulnerabilityLevel: 'High' },
    { sampleId: `${prefix}-community-2`, zoneId: `${prefix}-zone-2`, centerId: `${prefix}-center-2`, name: 'User Sample Hillside Community', population: 650, vulnerabilityLevel: 'Moderate' },
    { sampleId: `${prefix}-community-3`, zoneId: `${prefix}-zone-3`, centerId: `${prefix}-center-3`, name: 'User Sample Creekside Community', population: 1100, vulnerabilityLevel: 'Critical' }
  ];

  const incidentReports = [
    { sampleId: `${prefix}-incident-1`, communityId: `${prefix}-community-3`, title: 'User Sample Creek Water Alert', severity: 'High', description: 'Sample report for community-submitted monitoring.', reportedAt: new Date().toISOString() }
  ];

  const preparednessItems = [
    { sampleId: `${prefix}-check-1`, targetId: `${prefix}-community-1`, title: 'User sample warning contact list', status: 'In Progress', notes: 'Sample checklist item added by user.' },
    { sampleId: `${prefix}-check-2`, targetId: `${prefix}-center-1`, title: 'User sample supply area checked', status: 'Pending', notes: 'Sample center readiness item.' }
  ];

  try {
    await session.executeWrite(async (tx) => {
      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $hazardZones AS row
        MERGE (z:HazardZone {ownerId: $userId, sampleId: row.sampleId})
        SET z.name = row.name, z.type = row.type, z.riskLevel = row.riskLevel
        MERGE (u)-[:OWNS]->(z)
        `,
        { userId: req.user.id, hazardZones }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $evacuationCenters AS row
        MERGE (e:EvacuationCenter {ownerId: $userId, sampleId: row.sampleId})
        SET e.name = row.name, e.capacity = row.capacity, e.status = row.status
        MERGE (u)-[:OWNS]->(e)
        `,
        { userId: req.user.id, evacuationCenters }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $resources AS row
        MERGE (r:Resource {ownerId: $userId, sampleId: row.sampleId})
        SET r.type = row.type, r.quantity = row.quantity
        MERGE (u)-[:OWNS]->(r)
        WITH row, r
        MATCH (e:EvacuationCenter {ownerId: $userId, sampleId: row.centerId})
        MERGE (e)-[:HAS_STOCK]->(r)
        `,
        { userId: req.user.id, resources }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $communities AS row
        MERGE (c:Community {ownerId: $userId, sampleId: row.sampleId})
        SET c.name = row.name, c.population = row.population, c.vulnerabilityLevel = row.vulnerabilityLevel
        MERGE (u)-[:OWNS]->(c)
        WITH row, c
        MATCH (z:HazardZone {ownerId: $userId, sampleId: row.zoneId})
        MATCH (e:EvacuationCenter {ownerId: $userId, sampleId: row.centerId})
        MERGE (c)-[:LOCATED_IN]->(z)
        MERGE (c)-[:ASSIGNED_TO]->(e)
        MERGE (z)-[:THREATENS]->(c)
        MERGE (z)-[:THREATENS]->(e)
        `,
        { userId: req.user.id, communities }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $incidentReports AS row
        MERGE (i:IncidentReport {ownerId: $userId, sampleId: row.sampleId})
        SET i.title = row.title, i.severity = row.severity, i.description = row.description, i.reportedAt = row.reportedAt
        MERGE (u)-[:OWNS]->(i)
        WITH row, i
        MATCH (c:Community {ownerId: $userId, sampleId: row.communityId})
        MERGE (i)-[:AFFECTS]->(c)
        `,
        { userId: req.user.id, incidentReports }
      );

      await tx.run(
        `
        MATCH (u:AppUser {id: $userId})
        UNWIND $preparednessItems AS row
        MERGE (p:PreparednessItem {ownerId: $userId, sampleId: row.sampleId})
        SET p.title = row.title, p.status = row.status, p.notes = row.notes
        MERGE (u)-[:OWNS]->(p)
        WITH row, p
        MATCH (target {ownerId: $userId, sampleId: row.targetId})
        MERGE (p)-[:CHECKS]->(target)
        `,
        { userId: req.user.id, preparednessItems }
      );

      await writeAudit(tx, req.user.id, 'Seeded User Samples', 'Graph', 'User contributed sample set');
    });

    res.status(201).json({ message: 'Your sample graph data was added' });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

module.exports = router;
