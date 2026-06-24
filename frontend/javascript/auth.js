const API_BASE = '/api';

const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const submitBtn = document.getElementById('submitBtn');
const authMessage = document.getElementById('authMessage');

function showMessage(message, isError = true) {
  authMessage.textContent = message;
  authMessage.className = `rounded-md px-3 py-2 text-sm ${isError ? 'bg-rose-50 text-rose-700' : 'bg-emerald-50 text-emerald-700'}`;
  authMessage.classList.remove('hidden');
}

async function requestAuth(path, payload) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed with status ${response.status}`);
  }

  return response.json();
}

function saveSession(result) {
  localStorage.setItem('drrca-token', result.token);
  localStorage.setItem('drrca-user', JSON.stringify(result.user));
  window.location.href = './index.html';
}

if (localStorage.getItem('drrca-token')) {
  window.location.href = './index.html';
}

if (loginForm) {
  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    submitBtn.disabled = true;
    submitBtn.textContent = 'Logging in...';

    try {
      const result = await requestAuth('/auth/login', {
        email: document.getElementById('email').value.trim(),
        password: document.getElementById('password').value
      });
      saveSession(result);
    } catch (error) {
      showMessage(error.message);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Login';
    }
  });
}

if (registerForm) {
  registerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    submitBtn.disabled = true;
    submitBtn.textContent = 'Registering...';

    try {
      const result = await requestAuth('/auth/register', {
        name: document.getElementById('name').value.trim(),
        email: document.getElementById('email').value.trim(),
        password: document.getElementById('password').value
      });
      saveSession(result);
    } catch (error) {
      showMessage(error.message);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Register';
    }
  });
}
