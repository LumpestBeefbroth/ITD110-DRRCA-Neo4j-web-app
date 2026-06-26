const express = require('express');
const crypto = require('crypto');
const { neo4j, getSession, verifyConnection } = require('../config/db');

const router = express.Router();

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
  }
};

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
  return {
    id: user.id,
    name: user.name,
    email: user.email,
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
        MATCH (:AppUser {id: $userId})-[:OWNS]->(c:Community)
        MATCH (:AppUser {id: $userId})-[:OWNS]->(z:HazardZone)
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
        MATCH (:AppUser {id: $userId})-[:OWNS]->(c:Community)
        MATCH (:AppUser {id: $userId})-[:OWNS]->(e:EvacuationCenter)
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
        MATCH (:AppUser {id: $userId})-[:OWNS]->(z:HazardZone) WHERE elementId(z) = $nodeId
        MATCH (:AppUser {id: $userId})-[:OWNS]->(c:Community) WHERE elementId(c) IN $communityIds
        MERGE (z)-[:THREATENS]->(c)
        `,
        { nodeId, communityIds, userId }
      );
    }

    if (centerIds.length) {
      await tx.run(
        `
        MATCH (:AppUser {id: $userId})-[:OWNS]->(z:HazardZone) WHERE elementId(z) = $nodeId
        MATCH (:AppUser {id: $userId})-[:OWNS]->(e:EvacuationCenter) WHERE elementId(e) IN $centerIds
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
        MATCH (:AppUser {id: $userId})-[:OWNS]->(e:EvacuationCenter) WHERE elementId(e) = $nodeId
        MATCH (:AppUser {id: $userId})-[:OWNS]->(r:Resource) WHERE elementId(r) IN $resourceIds
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
        MATCH (:AppUser {id: $userId})-[:OWNS]->(e:EvacuationCenter)
        MATCH (:AppUser {id: $userId})-[:OWNS]->(r:Resource)
        WHERE elementId(e) = $evacuationCenterId AND elementId(r) = $nodeId
        MERGE (e)-[:HAS_STOCK]->(r)
        `,
        { nodeId, evacuationCenterId: String(relationships.evacuationCenterId), userId }
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
        { userId, name, email, passwordHash, salt, now, token, expiresAt }
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
        CREATE (s:AppSession {
          token: $token,
          createdAt: $now,
          expiresAt: $expiresAt
        })
        CREATE (u)-[:HAS_SESSION]->(s)
        `,
        { userId: props.id, token, now, expiresAt }
      );

      return userNode;
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
      MATCH (:AppUser {id: $userId})-[:OWNS]->(n:${label})
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
      `,
      { userId: req.user.id }
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
        MATCH (:AppUser {id: $userId})-[:OWNS]->(n:${label})
        WHERE elementId(n) = $id
        SET n += $properties
        RETURN n
        `,
        { id: req.params.id, properties, userId: req.user.id }
      );

      if (!result.records.length) {
        const error = new Error(`${label} not found`);
        error.status = 404;
        throw error;
      }

      await applyRelationships(tx, type, req.params.id, { ...relationships, userId: req.user.id }, true);
      const refreshed = await tx.run(
        `MATCH (:AppUser {id: $userId})-[:OWNS]->(n:${label}) WHERE elementId(n) = $id RETURN n`,
        { id: req.params.id, userId: req.user.id }
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

router.delete('/nodes/:type/:id', async (req, res, next) => {
  const session = getSession();

  try {
    const { label } = getNodeConfig(req.params.type);

    const deletedCount = await session.executeWrite(async (tx) => {
      const result = await tx.run(
        `
        MATCH (:AppUser {id: $userId})-[:OWNS]->(n:${label})
        WHERE elementId(n) = $id
        WITH n, count(n) AS deleted
        DETACH DELETE n
        RETURN deleted
        `,
        { id: req.params.id, userId: req.user.id }
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
      MATCH (:AppUser {id: $userId})-[:OWNS]->(c:Community)
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
      { name, userId: req.user.id }
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
      MATCH (:AppUser {id: $userId})-[:OWNS]->(n)
      WHERE any(label IN labels(n) WHERE label IN ['Community', 'HazardZone', 'EvacuationCenter', 'Resource'])
      UNWIND labels(n) AS label
      WITH label, count(*) AS count
      WHERE label IN ['Community', 'HazardZone', 'EvacuationCenter', 'Resource']
      RETURN label, count
      `,
      { userId: req.user.id }
    );

    const counts = {
      Community: 0,
      HazardZone: 0,
      EvacuationCenter: 0,
      Resource: 0
    };

    countsResult.records.forEach((record) => {
      counts[record.get('label')] = record.get('count').toNumber();
    });

    const capacityResult = await session.run(
      `
      MATCH (:AppUser {id: $userId})-[:OWNS]->(center:EvacuationCenter)
      OPTIONAL MATCH (community:Community)-[:ASSIGNED_TO]->(center)
      WHERE community IS NULL OR EXISTS {
        MATCH (:AppUser {id: $userId})-[:OWNS]->(community)
      }
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
      { userId: req.user.id }
    );

    const evacuationCapacity = capacityResult.records.map((record) => ({
      name: record.get('name') || 'Unnamed center',
      capacity: toNative(record.get('capacity')) || 0,
      assignedPopulation: toNative(record.get('assignedPopulation')) || 0,
      remainingCapacity: toNative(record.get('remainingCapacity')) || 0
    }));

    res.json({ counts, evacuationCapacity });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

router.get('/backup', async (req, res, next) => {
  const session = getSession(neo4j.session.READ);

  try {
    const nodesResult = await session.run(
      `
      MATCH (:AppUser {id: $userId})-[:OWNS]->(n)
      WHERE any(label IN labels(n) WHERE label IN ['Community', 'HazardZone', 'EvacuationCenter', 'Resource'])
      RETURN n
      ORDER BY labels(n)[0], coalesce(n.name, n.type)
      `,
      { userId: req.user.id }
    );

    const relationshipsResult = await session.run(
      `
      MATCH (:AppUser {id: $userId})-[:OWNS]->(a)-[r]->(b)
      MATCH (:AppUser {id: $userId})-[:OWNS]->(b)
      WHERE any(label IN labels(a) WHERE label IN ['Community', 'HazardZone', 'EvacuationCenter', 'Resource'])
        AND any(label IN labels(b) WHERE label IN ['Community', 'HazardZone', 'EvacuationCenter', 'Resource'])
      RETURN r
      ORDER BY type(r)
      `,
      { userId: req.user.id }
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

router.post('/seed-samples', async (req, res, next) => {
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
    });

    res.status(201).json({
      message: 'Sample graph data created',
      counts: {
        communities: communities.length,
        hazardZones: hazardZones.length,
        evacuationCenters: evacuationCenters.length,
        resources: resources.length
      }
    });
  } catch (error) {
    next(error);
  } finally {
    await session.close();
  }
});

module.exports = router;
