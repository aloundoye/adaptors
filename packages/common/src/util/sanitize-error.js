const REDACTED = '[REDACTED]';

const sensitiveKeys = new Set([
  'authorization',
  'proxyauthorization',
  'apikey',
  'xapikey',
  'accesstoken',
  'refreshtoken',
  'privatekey',
  'privatekeyid',
  'clientsecret',
  'cookie',
  'setcookie',
  'password',
  'passwd',
]);

const blockedDetailKeys = new Set([
  'config',
  'request',
  'response',
  'headers',
  'cause',
]);

const normalizeKey = key =>
  typeof key === 'string' ? key.toLowerCase().replace(/[^a-z0-9]/g, '') : '';

const isSensitiveKey = key => sensitiveKeys.has(normalizeKey(key));

const getDataProperty = (value, key) => {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && 'value' in descriptor ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
};

const readProperty = (value, key) => {
  try {
    return value?.[key];
  } catch {
    return undefined;
  }
};

const normalizeSecrets = secrets =>
  [...new Set((Array.isArray(secrets) ? secrets : [secrets]))].filter(
    secret => typeof secret === 'string' && secret.length > 0,
  );

const credentialPattern =
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+|\b(?:authorization|proxy[-_ ]?authorization|access[-_ ]?token|refresh[-_ ]?token|api[-_ ]?key|x[-_ ]?api[-_ ]?key|private[-_ ]?key(?:[-_ ]?id)?|client[-_ ]?secret|password|passwd|cookie|set[-_ ]?cookie)\s*[:=]\s*["']?(?!\[REDACTED\])[^\s,"';&}\]]+/i;

const containsSensitiveText = (value, secrets) =>
  secrets.some(secret => value.includes(secret)) || credentialPattern.test(value);

const redactText = (value, secrets) => {
  let result = value;

  for (const secret of secrets) {
    result = result.split(secret).join(REDACTED);
  }

  result = result.replace(
    /\b(authorization|proxy[-_ ]?authorization|access[-_ ]?token|refresh[-_ ]?token|api[-_ ]?key|x[-_ ]?api[-_ ]?key|private[-_ ]?key(?:[-_ ]?id)?|client[-_ ]?secret|password|passwd|cookie|set[-_ ]?cookie)(\s*[:=]\s*)["']?(?:(?:Bearer|Basic)\s+)?(?:\[REDACTED\]|[^\s,"';&}\]]+)/gi,
    `$1$2${REDACTED}`,
  );
  result = result.replace(
    /\b(Bearer|Basic)\s+(?!\[REDACTED\])[A-Za-z0-9._~+/=-]+/gi,
    `$1 ${REDACTED}`,
  );

  return result;
};

const containsSensitiveMaterial = (value, secrets, seen = new WeakSet()) => {
  if (typeof value === 'string') {
    return containsSensitiveText(value, secrets);
  }

  if ((typeof value !== 'object' && typeof value !== 'function') || !value) {
    return false;
  }

  if (seen.has(value)) return false;
  seen.add(value);

  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    return false;
  }

  for (const key of keys) {
    if (isSensitiveKey(key)) return true;

    const propertyValue = getDataProperty(value, key);
    if (containsSensitiveMaterial(propertyValue, secrets, seen)) return true;
  }

  return false;
};

const sanitizeDetails = (value, secrets, seen = new WeakMap()) => {
  if (typeof value === 'string') return redactText(value, secrets);
  if (value === null || typeof value !== 'object') return value;

  if (seen.has(value)) return '[Circular]';

  const result = Array.isArray(value) ? [] : {};
  seen.set(value, result);

  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    return '[Unavailable]';
  }

  for (const key of keys) {
    if (typeof key !== 'string') continue;

    const normalizedKey = normalizeKey(key);
    if (blockedDetailKeys.has(normalizedKey)) continue;

    if (isSensitiveKey(key)) {
      result[key] = REDACTED;
      continue;
    }

    const propertyValue = getDataProperty(value, key);
    if (propertyValue === undefined || typeof propertyValue === 'function') {
      continue;
    }
    result[key] = sanitizeDetails(propertyValue, secrets, seen);
  }

  return result;
};

const readServiceErrors = error => {
  if (Array.isArray(error)) return error;
  if (!error || (typeof error !== 'object' && typeof error !== 'function')) {
    return undefined;
  }

  const errors = getDataProperty(error, 'errors');
  if (errors !== undefined) return errors;

  const response = getDataProperty(error, 'response');
  const data = response && getDataProperty(response, 'data');
  if (!data || typeof data !== 'object') return undefined;

  const responseErrors = getDataProperty(data, 'errors');
  if (responseErrors !== undefined) return responseErrors;

  const responseError = getDataProperty(data, 'error');
  return responseError && getDataProperty(responseError, 'errors');
};

const readMessage = (error, secrets) => {
  if (typeof error === 'string') return redactText(error, secrets);

  const message =
    error && (typeof error === 'object' || typeof error === 'function')
      ? readProperty(error, 'message')
      : undefined;

  if (typeof message === 'string') return redactText(message, secrets);

  if (Array.isArray(error)) {
    try {
      return JSON.stringify(sanitizeDetails(error, secrets));
    } catch {
      return 'Operation failed';
    }
  }

  return redactText(String(error), secrets);
};

/**
 * Removes credentials and transport metadata from an error before it leaves an
 * adaptor. Non-sensitive errors are returned unchanged.
 *
 * Security guidance: wiki/best-practice.md#security-considerations
 *
 * @public
 * @param {*} error - The value thrown by an operation or client library.
 * @param {string|string[]} [secrets=[]] - Credential values to redact wherever
 * they appear in diagnostic text.
 * @returns {*} The original value when safe, otherwise a sanitized Error.
 */
export function sanitizeError(error, secrets = []) {
  const normalizedSecrets = normalizeSecrets(secrets);
  if (!containsSensitiveMaterial(error, normalizedSecrets)) return error;

  const safeError = new Error(readMessage(error, normalizedSecrets));

  const name = readProperty(error, 'name');
  if (typeof name === 'string') {
    safeError.name = redactText(name, normalizedSecrets);
  }

  const stack = readProperty(error, 'stack');
  if (typeof stack === 'string') {
    safeError.stack = redactText(stack, normalizedSecrets);
  }

  for (const key of ['code', 'status', 'statusCode']) {
    const value = readProperty(error, key);
    if (['string', 'number', 'boolean'].includes(typeof value)) {
      safeError[key] =
        typeof value === 'string'
          ? redactText(value, normalizedSecrets)
          : value;
    }
  }

  const serviceErrors = readServiceErrors(error);
  if (serviceErrors !== undefined) {
    safeError.errors = sanitizeDetails(serviceErrors, normalizedSecrets);
  }

  return safeError;
}
