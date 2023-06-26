import { expect } from 'chai';
import { execute, dataValue, createFhirResource } from '../src/Adaptor.js';

import MockAgent from './mockAgent.js';
import { setGlobalDispatcher } from 'undici';

setGlobalDispatcher(MockAgent);

describe('execute', () => {
  it('executes each operation in sequence', done => {
    const state = {};
    const operations = [
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

  it('assigns references, data to the initialState', () => {
    const state = {};

    execute()(state).then(finalState => {
      expect(finalState).to.eql({ references: [], data: null });
    });
  });
});

describe('createFhirResource', () => {
  it('creates a patient resource to google cloud healthcare', async () => {
    const state = {
      configuration: {
        cloudRegion: 'us-east7',
        projectId: 'test-007',
        datasetId: 'fhir-007',
        fhirStoreId: 'testing-fhir-007',
        accessToken: 'aGVsbG86dGhlcmU=',
      },
      data: {
        resourceType: 'Patient',
        name: [{ use: 'official', family: 'Smith', given: ['Darcy'] }],
        gender: 'female',
        birthDate: '1970-01-01',
      },
    };

    const finalState = await execute(createFhirResource(state => state.data))(
      state
    );

    expect(finalState.data).to.eql({
      birthDate: '1970-01-01',
      gender: 'female',
      id: '08ab7dd6-4271-45b2-a6a7-0ecd5ddce29d',
      meta: {
        lastUpdated: '2023-06-23T16:40:46.202757+00:00',
        versionId: 'MTY4NzUzODQ0NjIwMjc1NzAwMA',
      },
      name: [
        {
          family: 'Smith',
          given: ['Darcy'],
          use: 'official',
        },
      ],
      resourceType: 'Patient',
    });
  });

  it.skip('throws an error for a 404', async () => {
    const state = {
      configuration: {
        baseUrl: 'https://fake.server.com',
        username: 'hello',
        password: 'there',
      },
    };

    const error = await execute(
      createFhirResource('noAccess', { name: 'taylor' })
    )(state).catch(error => {
      return error;
    });

    expect(error.message).to.eql('Page not found');
  });

  it.skip('handles and throws different kinds of errors', async () => {
    const state = {
      configuration: {
        baseUrl: 'https://fake.server.com',
        username: 'hello',
        password: 'there',
      },
    };

    const error = await execute(
      createFhirResource('!@#$%^&*', { name: 'taylor' })
    )(state).catch(error => {
      return error;
    });

    expect(error.message).to.eql('Server error');
  });
});
