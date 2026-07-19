import { expect } from 'chai';
import { inspect } from 'node:util';
import { serializeError } from 'serialize-error';
import {
  getGlobalDispatcher,
  MockAgent,
  setGlobalDispatcher,
} from 'undici';

import { execute, prompt } from '../src/Adaptor';

const sentinel = 'sentinel-google-credential-1706';

const assertSecretAbsent = (error: Error) => {
  expect(error.message).not.to.include(sentinel);
  expect(inspect(error, { depth: null })).not.to.include(sentinel);
  expect(JSON.stringify(serializeError(error))).not.to.include(sentinel);
};

describe('Gemini error handling', () => {
  const originalDispatcher = getGlobalDispatcher();
  let mockAgent: MockAgent;

  beforeEach(() => {
    mockAgent = new MockAgent();
    mockAgent.disableNetConnect();
    setGlobalDispatcher(mockAgent);
  });

  afterEach(async () => {
    await mockAgent.close();
    setGlobalDispatcher(originalDispatcher);
  });

  it('does not expose the API key from prompt errors', async () => {
    mockAgent
      .get('https://generativelanguage.googleapis.com')
      .intercept({
        path: /\/v1beta\/models\/gemini-2\.5-flash-lite:generateContent/,
        method: 'POST',
        headers: {
          'x-goog-api-key': sentinel,
        },
      })
      .reply(500, {
        error: {
          code: 500,
          message: `apiKey=${sentinel} must not escape`,
          status: 'INTERNAL',
        },
      });

    const error = await execute(prompt('hello'))({
      configuration: { apiKey: sentinel },
    }).catch((error: Error) => error);

    expect(error.message).to.include('INTERNAL');
    assertSecretAbsent(error);
  });
});

