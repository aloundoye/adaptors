import Adaptor from '../src/index.js';
import { expect } from 'chai';
import nock from 'nock';
import { BigQuery } from '@google-cloud/bigquery';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { serializeError } from 'serialize-error';

const { execute, load, parseCSV, alterState } = Adaptor;
const sentinel = 'sentinel-google-credential-1706';
const assetsPath = fileURLToPath(new URL('../assets', import.meta.url));

const assertSecretAbsent = error => {
  expect(error.message).not.to.include(sentinel);
  expect(inspect(error, { depth: null })).not.to.include(sentinel);
  expect(JSON.stringify(serializeError(error))).not.to.include(sentinel);
};

describe('The execute() function', () => {
  it('executes each operation in sequence', done => {
    let state = {};
    let operations = [
      state => {
        return { counter: 1 };
      },
      state => {
        return { counter: 2 };
      },
      state => {
        return { counter: 3 };
      },
    ];

    execute(...operations)(state)
      .then(finalState => {
        expect(finalState).to.eql({ counter: 3 });
      })
      .then(done)
      .catch(done);
  });

  it('assigns references, data to the initialState', done => {
    let state = {};

    let finalState = execute()(state);

    execute()(state)
      .then(finalState => {
        expect(finalState).to.eql({
          references: [],
          data: null,
        });
      })
      .then(done)
      .catch(done);
  });
});

describe('load()', () => {
  let originalDataset;
  let table;
  let loadedFiles;

  beforeEach(() => {
    originalDataset = BigQuery.prototype.dataset;
    loadedFiles = [];
    table = {
      get: async () => [
        {
          metadata: {
            tableReference: {
              projectId: 'project',
              datasetId: 'dataset',
              tableId: 'table',
            },
          },
        },
      ],
      load: async fileName => {
        loadedFiles.push(fileName);
        return [
          {
            id: 'job-id',
            configuration: { load: { schema: { fields: [] } } },
            status: {},
          },
        ];
      },
    };

    BigQuery.prototype.dataset = () => ({
      table: () => table,
    });
  });

  afterEach(() => {
    BigQuery.prototype.dataset = originalDataset;
  });

  it('loads files with the current BigQuery client', async () => {
    const state = await execute(
      load(assetsPath, 'project', 'dataset', 'table', {}),
    )({ configuration: {} });

    expect(state.data).to.equal(null);
    expect(loadedFiles).not.to.be.empty;
  });

  it('does not expose credentials from client errors', async () => {
    const clientError = new Error('BigQuery request failed');
    clientError.code = 400;
    clientError.response = {
      request: { headers: { Authorization: `Bearer ${sentinel}` } },
      data: {
        error: {
          errors: [{ reason: 'invalid', message: 'Invalid request' }],
        },
      },
    };
    table.get = async () => {
      throw clientError;
    };

    const error = await execute(
      load(assetsPath, 'project', 'dataset', 'table', {}),
    )({ configuration: { private_key: 'service-account-private-key' } }).catch(
      error => error,
    );

    expect(error.code).to.equal(400);
    expect(error.errors).to.deep.equal([
      { reason: 'invalid', message: 'Invalid request' },
    ]);
    expect(error).not.to.have.property('response');
    assertSecretAbsent(error);
  });
});

// TODO: write test for parseCSV() function
