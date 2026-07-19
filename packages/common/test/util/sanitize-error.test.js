import { expect } from 'chai';
import { inspect } from 'node:util';
import { serializeError } from 'serialize-error';

import { sanitizeError } from '../../src/util/sanitize-error.js';

const sentinel = 'sentinel-google-credential-1706';

const assertSecretAbsent = error => {
  expect(error.message).not.to.include(sentinel);
  expect(inspect(error, { depth: null })).not.to.include(sentinel);
  expect(JSON.stringify(serializeError(error))).not.to.include(sentinel);
};

describe('sanitizeError', () => {
  it('removes nested transport credentials and preserves safe diagnostics', () => {
    const error = new Error('Google request failed');
    error.code = 'ERR_STREAM_PREMATURE_CLOSE';
    error.status = 401;
    error.statusCode = 401;
    error.config = {
      headers: { Authorization: `Bearer ${sentinel}` },
    };
    error.response = {
      request: { headers: { authorization: `Bearer ${sentinel}` } },
      data: {
        error: {
          errors: [
            {
              reason: 'authError',
              message: `Authorization: Bearer ${sentinel}`,
              access_token: sentinel,
            },
          ],
        },
      },
    };

    const result = sanitizeError(error, 'a-different-configured-secret');

    expect(result).not.to.equal(error);
    expect(result).to.be.an.instanceOf(Error);
    expect(result.message).to.equal('Google request failed');
    expect(result.code).to.equal('ERR_STREAM_PREMATURE_CLOSE');
    expect(result.status).to.equal(401);
    expect(result.statusCode).to.equal(401);
    expect(result).not.to.have.property('config');
    expect(result).not.to.have.property('request');
    expect(result).not.to.have.property('response');
    expect(result.errors[0]).to.deep.equal({
      reason: 'authError',
      message: 'Authorization: [REDACTED]',
      access_token: '[REDACTED]',
    });
    assertSecretAbsent(result);
  });

  it('redacts configured secrets embedded in messages and stacks', () => {
    const error = new Error(`Request failed for ${sentinel}`);
    error.stack = `Error: Request failed\nAuthorization: Bearer ${sentinel}`;

    const result = sanitizeError(error, [sentinel]);

    expect(result.message).to.equal('Request failed for [REDACTED]');
    expect(result.stack).to.include('Authorization: [REDACTED]');
    assertSecretAbsent(result);
  });

  it('handles circular, inaccessible, array, and non-Error values', () => {
    const thrown = [
      { message: 'Authentication failed', apiKey: sentinel },
    ];
    thrown.push(thrown);
    Object.defineProperty(thrown, 'inaccessible', {
      get() {
        throw new Error('getter should not run');
      },
    });

    const result = sanitizeError(thrown, sentinel);

    expect(result).to.be.an.instanceOf(Error);
    expect(result.errors[0]).to.deep.equal({
      message: 'Authentication failed',
      apiKey: '[REDACTED]',
    });
    expect(result.errors[1]).to.equal('[Circular]');
    assertSecretAbsent(result);

    const stringResult = sanitizeError(`Bearer ${sentinel}`, sentinel);
    expect(stringResult).to.be.an.instanceOf(Error);
    assertSecretAbsent(stringResult);
  });

  it('returns non-sensitive thrown values unchanged', () => {
    const error = new Error('A validation rule failed');
    error.code = 'VALIDATION_ERROR';
    const object = { message: 'A plain thrown value', retryable: false };

    expect(sanitizeError(error, sentinel)).to.equal(error);
    expect(sanitizeError(object, sentinel)).to.equal(object);
  });
});
