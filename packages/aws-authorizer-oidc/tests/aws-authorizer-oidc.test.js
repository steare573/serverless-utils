import fetch from 'node-fetch';
import URLSearchParams from 'url-search-params';
import { createAuthorizer, hooks } from '../src';

// NOTE: In order to get a valid jwt from auth0, not all of these tests are "unit" tests (but)
// rather integration tests.  In the future, refactor tests to sign our own tokens and stub
// the auth0 calls with the nock modules to return our internally generated token.
describe('src/index', () => {
  describe('hooks export', () => {
    it('contains the proper public properties', () => {
      expect(hooks.generatePrincipalId.default).toBeInstanceOf(Function);
      expect(hooks.postPolicyGeneration.default).toBeInstanceOf(Function);
    });
  });
  describe('createAuthorizer', () => {
    it('returns a function', () => {
      const authorizer = createAuthorizer({ methodsApplied: ['GET'] });
      expect(authorizer).toBeInstanceOf(Function);
    });

    it('throws error with no config passed', () => {
      expect(() => {
        createAuthorizer();
      })
        .toThrow('Invalid config: Must supply either pathMappings or methodsApplied');
    });

    it('throws error if neither pathmappings or applied methods allowed', () => {
      expect(() => createAuthorizer({}))
        .toThrow('Invalid config: Must supply either pathMappings or methodsApplied');
    });

    // Tests on the generated function
    describe('returns authorizer function that', () => {
      const readAuthorizer = createAuthorizer({
        pathMapping: {
          GET: ['testget'],
          POST: ['testpost'],
        },
        acceptedScopes: ['write:resource'],
        jwksUri: 'https://steare573.auth0.com/.well-known/jwks.json',
        jwtAudiences: ['https://localhost:3000'],
        jwtIssuer: 'https://steare573.auth0.com/',
      });

      const failAuthorizer = createAuthorizer({
        pathMapping: {
          GET: ['failfailfail'],
        },
        jwksUri: 'https://steare573.auth0.com/.well-known/jwks.json',
        jwtAudiences: ['https://localhost:3000'],
        jwtIssuer: 'https://steare573.auth0.com/',
      });

      const eventObj = {
        type: 'REQUEST',
        path: '/steare/authorizer-test',
        httpMethod: 'DELETE',
        headers: {
          authorization: '',
          'cache-control': 'no-cache',
          accept: '*/*',
          host: 'localhost:3000',
          'content-type': 'application/x-www-form-urlencoded',
          'accept-encoding': 'gzip, deflate',
          'content-length': '0',
          connection: 'keep-alive',
          'Cache-Control': 'no-cache',
          Authorization: '',
          'User-Agent': 'PostmanRuntime/7.3.0',
          Accept: '*/*',
          Host: 'localhost:3000',
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept-Encoding': 'gzip, deflate',
          'Content-Length': '0',
          Connection: 'keep-alive',
        },
        pathParameters: null,
        queryStringParameters: null,
        methodArn: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/steare/authorizer-test',
      };
      const emptyEventObj = JSON.parse(JSON.stringify(eventObj));

      const contextObj = {};
      beforeAll((done) => {
        const params = new URLSearchParams();
        // note this is a test user, hence the creds here
        params.append('grant_type', 'client_credentials');
        params.append('client_id', process.env.TEST_AUTH_CLIENT_ID);
        params.append('client_secret', process.env.TEST_AUTH_CLIENT_SECRET);
        params.append('audience', 'https://localhost:3000');

        fetch(
          'https://steare573.auth0.com/oauth/token',
          {
            method: 'POST',
            body: params,
          },
        ).then(res => res.json())
          .then((data) => {
            eventObj.headers.Authorization = `Bearer ${data.access_token}`;
            eventObj.headers.authorization = `Bearer ${data.access_token}`;
            done();
          });
      });

      it('doesnt error if no callback passed', (done) => {
        // dont really know of another way to test this, so just setting a timeout
        // to make sure it doesn't error within 5 seconds.  I know this is a hack
        readAuthorizer(eventObj, contextObj);
        setTimeout(() => done(), 4500);
      });

      it('doesnt allow access if no auth token', (done) => {
        readAuthorizer(emptyEventObj, contextObj, (err) => {
          expect(err).toEqual('Unauthorized');
          return done();
        });
      });

      it('denies access if jwt is invalid (expired)', (done) => {
        const invalidJwtEvent = JSON.parse(JSON.stringify(emptyEventObj));
        const params = new URLSearchParams();
        params.append('grant_type', 'client_credentials');
        params.append('client_id', process.env.TEST_AUTH_CLIENT_ID);
        params.append('client_secret', process.env.TEST_AUTH_CLIENT_SECRET);
        params.append('audience', 'https://localhost:3000');

        invalidJwtEvent.headers.authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA';

        readAuthorizer(invalidJwtEvent, contextObj, (err) => {
          expect(err).toEqual('Unauthorized');
          return done();
        });
      });

      it('allows access if token has correct scope', (done) => {
        /* eslint-disable consistent-return */
        readAuthorizer(eventObj, contextObj, (err, data) => {
          if (err) return done(err);
          expect(data).toMatchObject({
            principalId: 'user',
            policyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Action: 'execute-api:Invoke',
                  Effect: 'Allow',
                  Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/testget',
                },
                {
                  Action: 'execute-api:Invoke',
                  Effect: 'Allow',
                  Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/POST/testpost',
                },
              ],
            },
          });
          done();
        });
      });

      it('denies access if token doesnt have right scope', (done) => {
        failAuthorizer(eventObj, contextObj, (err, data) => {
          expect(err).toBeUndefined();
          expect(data).toMatchObject({
            principalId: 'user',
            policyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Action: 'execute-api:Invoke',
                  Effect: 'Deny',
                  Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/failfailfail',
                },
              ],
            },
          });
          return done();
        });
      });

      it('executes postPolicyGeneration hook properly with proper inputs', (done) => {
        const hookAuthorizer = createAuthorizer({
          pathMapping: {
            GET: ['testget'],
            POST: ['testpost'],
          },
          acceptedScopes: ['write:resource'],
          jwksUri: 'https://steare573.auth0.com/.well-known/jwks.json',
          jwtAudiences: ['https://localhost:3000'],
          jwtIssuer: 'https://steare573.auth0.com/',
          hooks: {
            postPolicyGeneration: async (data) => {
              expect(Object.keys(data)).toEqual(expect.arrayContaining(['policy', 'event', 'context', 'decodedJwt']));
              return data.policy;
            },
          },
        });
        hookAuthorizer(eventObj, contextObj, (err, data) => {
          expect(err).toBeUndefined();
          expect(data).toMatchObject({
            principalId: 'user',
            policyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Action: 'execute-api:Invoke',
                  Effect: 'Allow',
                  Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/testget',
                },
                {
                  Action: 'execute-api:Invoke',
                  Effect: 'Allow',
                  Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/POST/testpost',
                },
              ],
            },
          });
          done();
        });
      });

      it('it returns original policy if no postPolicyGeneration hook', (done) => {
        const hookAuthorizer = createAuthorizer({
          pathMapping: {
            GET: ['testget'],
            POST: ['testpost'],
          },
          acceptedScopes: ['write:resource'],
          jwksUri: 'https://steare573.auth0.com/.well-known/jwks.json',
          jwtAudiences: ['https://localhost:3000'],
          jwtIssuer: 'https://steare573.auth0.com/',
          hooks: {
            postPolicyGeneration: undefined,
          },
        });
        hookAuthorizer(eventObj, contextObj, (err, data) => {
          expect(err).toBeUndefined();
          expect(data).toMatchObject({
            principalId: 'user',
            policyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Action: 'execute-api:Invoke',
                  Effect: 'Allow',
                  Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/testget',
                },
                {
                  Action: 'execute-api:Invoke',
                  Effect: 'Allow',
                  Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/POST/testpost',
                },
              ],
            },
          });
          done();
        });
      });
      it('it returns error if postPolicyGeneration returns error', (done) => {
        const hookAuthorizerFail = createAuthorizer({
          pathMapping: {
            GET: ['testget'],
            POST: ['testpost'],
          },
          acceptedScopes: ['write:resource'],
          jwksUri: 'https://steare573.auth0.com/.well-known/jwks.json',
          jwtAudiences: ['https://localhost:3000'],
          jwtIssuer: 'https://steare573.auth0.com/',
          hooks: {
            postPolicyGeneration: (data, cb) => {
              expect(Object.keys(data)).toEqual(expect.arrayContaining(['policy', 'event', 'context', 'decodedJwt']));
              expect(cb).toBeInstanceOf(Function);
              return cb(new Error('Test error'));
            },
          },
        });
        hookAuthorizerFail(eventObj, contextObj, (err) => {
          expect(err).toEqual('Unauthorized');
          return done();
        });
      });
    });
  });
});
