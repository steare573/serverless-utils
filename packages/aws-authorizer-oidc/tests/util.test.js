import pq from 'proxyquire';
import util, {
  generateStatements,
  generatePolicy,
  normalizeConfig,
  validateConfig,
  getRequestEventAccessToken,
  getTokenEventAccessToken,
  getAccessToken,
  extractJwtData,
  getPrincipalId,
  defaultGeneratePrincipalId,
  defaultPostPolicyGeneration,
} from '../src/util';

const proxyquire = pq.noPreserveCache();

describe('/src/util', () => {
  // exportable interface
  it('contains all necessary functions', () => {
    [
      'generateStatements',
      'generatePolicy',
      'normalizeConfig',
      'validateConfig',
      'generateJwksClient',
      'getAccessToken',
      'extractJwtData',
      'getRequestEventAccessToken',
      'getTokenEventAccessToken',
      'getPrincipalId',
    ].forEach((key) => {
      expect(util[key]).toBeInstanceOf(Function);
    });
  });

  // tests for normalize config function
  describe('normalizeConfig', () => {
    it('produces defaults with empty input config', () => {
      const config = normalizeConfig();

      expect(config).toMatchObject({
        methodsApplied: [],
        acceptedScopes: [],
        hooks: {},
      });
      expect(Object.keys(config.hooks)).toEqual(expect.arrayContaining([
        'postPolicyGeneration',
        'generatePrincipalId',
      ]));
      expect(config.hooks.postPolicyGeneration).toBeInstanceOf(Function);
      expect(config.hooks.generatePrincipalId).toBeInstanceOf(Function);
    });

    it('overrides defaults with user input', () => {
      const userConfig = {
        jwksUri: 'testuri',
        jwtAudiences: ['testaudience'],
        jwtIssuer: 'testissuer',
        acceptedScopes: ['scope1', 'scope2'],
      };
      const config = normalizeConfig(userConfig);

      expect(config).toMatchObject({
        ...userConfig,
        methodsApplied: [],
        acceptedScopes: ['scope1', 'scope2'],
      });
    });
    it('overrides defaults with environment variables', () => {
      process.env.AUTHORIZER_ACCEPTED_AUDIENCES = 'testaud1, testaud2';
      process.env.AUTHORIZER_JWKS_URI = 'https://jwks.com';
      process.env.AUTHORIZER_ACCEPTED_ISSUER = 'https://issuer.com';
      // proxyquire will allow us to ignore the built-in module caching so we can re-load the
      // environment variables set abbove.
      const utils = proxyquire('../src/util', {});
      const normalizedConf = utils.normalizeConfig();
      expect(normalizedConf).toMatchObject({
        jwksUri: 'https://jwks.com',
        jwtAudiences: ['testaud1', 'testaud2'],
        jwtIssuer: 'https://issuer.com',
        methodsApplied: [],
        acceptedScopes: [],
        pathMapping: {},
      });
    });
  });
  // tests for validate config function
  describe('validateConfig', () => {
    it('throws error if no config passed in', () => {
      expect(() => {
        validateConfig();
      }).toThrow('Config must be an object');
    });

    it('returns true on properly formatted config', () => {
      expect(validateConfig({
        pathMapping: {
          GET: ['this'],
        },
      })).toEqual(true);
    });
  });

  // tests for getTokenEventAccessToken function
  describe('getTokenEventAccessToken', () => {
    it('parses an aws event of type token correctly', () => {
      const event = {
        type: 'TOKEN',
        authorizationToken: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA',
        methodArn: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/steare/authorizer-test',
      };
      const accessToken = getTokenEventAccessToken(event);
      expect(accessToken).toEqual('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA');
    });
    it('throws an error if non-bearer auth type', () => {
      const event = {
        type: 'TOKEN',
        authorizationToken: 'Basic ZWx1c3VhcmlvOnlsYWNsYXZl',
        methodArn: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/steare/authorizer-test',
      };
      expect(() => {
        getTokenEventAccessToken(event);
      }).toThrow('Only bearer tokens supported');
    });
    it('throws an error on mal-formed event object', () => {

    });

    it('throws an error on empty event', () => {
      expect(() => {
        getTokenEventAccessToken();
      }).toThrow('No authorization token present');
    });
  });

  // tests for getRequestEventAccessToken function
  describe('getRequestEventAccessToken', () => {
    it('parses an aws event of type request correctly', () => {
      const event = {
        type: 'REQUEST',
        path: '/steare/authorizer-test',
        httpMethod: 'DELETE',
        headers: {
          authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA',
          'cache-control': 'no-cache',
          'postman-token': '60d33cdb-56fa-480f-8716-4669818c12e1',
          'user-agent': 'PostmanRuntime/7.3.0',
          accept: '*/*',
          host: 'localhost:3000',
          'content-type': 'application/x-www-form-urlencoded',
          'accept-encoding': 'gzip, deflate',
          'content-length': '0',
          connection: 'keep-alive',
          'Cache-Control': 'no-cache',
          Authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA',
          'User-Agent': 'PostmanRuntime/7.3.0',
          Accept: '*/*',
          Host: 'localhost:3000',
          'Content-Type':
          'application/x-www-form-urlencoded',
          'Accept-Encoding': 'gzip, deflate',
          'Content-Length': '0',
          Connection: 'keep-alive',
        },
        pathParameters: null,
        queryStringParameters: null,
        methodArn: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/steare/authorizer-test',
      };
      const accessToken = getRequestEventAccessToken(event);
      expect(accessToken).toEqual('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA');
    });

    it('throws an error if non-bearer auth type', () => {
      const event = {
        type: 'REQUEST',
        path: '/steare/authorizer-test',
        httpMethod: 'DELETE',
        headers: {
          authorization: 'Basic ZWx1c3VhcmlvOnlsYWNsYXZl',
        },
      };

      expect(() => {
        getRequestEventAccessToken(event);
      }).toThrow('Only bearer tokens supported');
    });
    it('throws an error on mal-formed event object', () => {

    });

    it('throws an error on empty event', () => {
      expect(() => {
        getRequestEventAccessToken();
      }).toThrow('No authorization header present');
    });
  });

  // tests for getAccessToken function
  describe('getAccessToken', () => {
    it('gets acccess token if event is of type request', () => {
      const event = {
        type: 'REQUEST',
        path: '/steare/authorizer-test',
        httpMethod: 'DELETE',
        headers: {
          authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA',
          'cache-control': 'no-cache',
          'postman-token': '60d33cdb-56fa-480f-8716-4669818c12e1',
          'user-agent': 'PostmanRuntime/7.3.0',
          accept: '*/*',
          host: 'localhost:3000',
          'content-type': 'application/x-www-form-urlencoded',
          'accept-encoding': 'gzip, deflate',
          'content-length': '0',
          connection: 'keep-alive',
          'Cache-Control': 'no-cache',
          Authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA',
          'User-Agent': 'PostmanRuntime/7.3.0',
          Accept: '*/*',
          Host: 'localhost:3000',
          'Content-Type':
          'application/x-www-form-urlencoded',
          'Accept-Encoding': 'gzip, deflate',
          'Content-Length': '0',
          Connection: 'keep-alive',
        },
        pathParameters: null,
        queryStringParameters: null,
        methodArn: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/steare/authorizer-test',
      };
      const accessToken = getAccessToken(event);
      expect(accessToken).toEqual('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA');
    });
    it('gets access token if event is of type token', () => {
      const event = {
        type: 'TOKEN',
        authorizationToken: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA',
        methodArn: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/steare/authorizer-test',
      };
      const accessToken = getAccessToken(event);
      expect(accessToken).toEqual('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA');
    });
    it('throws error on unsupported requeset type', () => {
      expect(() => {
        getAccessToken({ type: 'Unsupported' });
      }).toThrow('Unsupported event type Unsupported');
    });
    it('throws error if no event passed in', () => {
      expect(() => {
        getAccessToken();
      }).toThrow('No authorization token present');
    });
  });

  // tests for extractJwtData function
  describe('extractJwtData', () => {
    const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJVRkRRekF3TlVZNFJESTBSREV4TWpJMk5EZEJPRVEyTWtKQk16UTRNRFZGTnpOQlJVRXdSUSJ9.eyJpc3MiOiJodHRwczovL3Bhc3Nwb3J0aW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJKclY1SHd6YUd2NklaVGVwODZRb2VmbUNmMlQySDFRYUBjbGllbnRzIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiaWF0IjoxNTM3NDU3Njc2LCJleHAiOjE1Mzc1NDQwNzYsImF6cCI6IkpyVjVId3phR3Y2SVpUZXA4NlFvZWZtQ2YyVDJIMVFhIiwic2NvcGUiOiJ3cml0ZTp0ZXN0IHdyaXRlOnZlaGljbGVzIHJlYWQ6dmVoaWNsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.RI2QyWRTEvbAwd2X9nO9tr9DNujwlPO_7x7JafjBYzHT1JtwDFob34qPmjwD7XDA9vMYOnKu_h74LmYkrT8JL96n0aoTP9OekeFYYrCgqZHW6buUTshltKDRUHO6-w-qx79T1x8W8TAlPlczAaXyntBrjHMWLfwPbAOWvyEQYM6FQ92m4FW0u65e_hb_bycFO8R6h0ZUR4YGG54fepwylwgq90qpirnjbOWVTBYklWgOTZTo4-k4FoOKATX-Ayf0pE8zQ1ocCOif_lOOKc-3iB31cuDqoTdGB5jcaK_ZlZVL10Pz4LL9kTXKEoVjTtJAhzaMiY9JS5Ff-bNAszOIVA';
    it('properly extracts kid aand scopes from well-formed jwt', () => {
      const jwtData = extractJwtData(jwt);
      expect(jwtData).toMatchObject({
        kid: 'RUFDQzAwNUY4RDI0RDExMjI2NDdBOEQ2MkJBMzQ4MDVFNzNBRUEwRQ',
        scopes: ['write:test', 'write:vehicles', 'read:vehicles'],
      });
    });

    it('throws error on mal-formed jwt', () => {
      expect(() => {
        extractJwtData(`as234afa.${jwt}blahblahblah`);
      }).toThrow('Error parsing jwt token. Token may be malformed');
    });
  });

  describe('generatePolicy', () => {
    it('', () => {

    });
  });

  describe('generateStatements', () => {
    it('generates a statement array correctly without path mapping', () => {
      const statements = generateStatements(
        'Allow',
        'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/authorizer-test',
        ['DELETE', 'GET', 'POST'],
      );

      expect(statements).toEqual(expect.arrayContaining([
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/authorizer-test',
        },
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/authorizer-test/*',
        },
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/authorizer-test',
        },
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/authorizer-test/*',
        },
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/POST/authorizer-test',
        },
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/POST/authorizer-test/*',
        },
      ]));
    });

    it('generates a statement array correctly with path mapping', () => {
      const statements = generateStatements(
        'Allow',
        'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/authorizer-test',
        undefined,
        {
          GET: [
            'steare/authorizer/*',
            'whatever/new/route/now',
          ],
          POST: [
            'post/route',
          ],
          DELETE: [],
        },
      );

      expect(statements).toEqual(expect.arrayContaining([
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/steare/authorizer/*',
        },
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/whatever/new/route/now',
        },
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/POST/post/route',
        },
      ]));
    });
    it('does not create a statement if the method currently called isnt accepted method', () => {
      expect(true).toEqual(true);
    });

    it('throws error on missing parameters', () => {
      expect(() => {
        generateStatements();
      }).toThrow('Missing effect to generate policy statements');

      expect(() => {
        generateStatements({});
      }).toThrow('Missing resource to generate policy statements');
    });
  });

  describe('generatePolicy', () => {
    it('generates a policy correctly', () => {
      const policy = generatePolicy(
        'principalId',
        'Allow',
        'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/authorizer-test',
        ['DELETE', 'GET', 'POST'],
      );
      expect(
        policy,
      ).toMatchObject({
        principalId: 'principalId',
        policyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Action: 'execute-api:Invoke',
              Effect: 'Allow',
              Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/authorizer-test',
            },
            {
              Action: 'execute-api:Invoke',
              Effect: 'Allow',
              Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/DELETE/authorizer-test/*',
            },
            {
              Action: 'execute-api:Invoke',
              Effect: 'Allow',

              Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/authorizer-test',
            },
            {
              Action: 'execute-api:Invoke',
              Effect: 'Allow',
              Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/GET/authorizer-test/*',
            },
            {
              Action: 'execute-api:Invoke',
              Effect: 'Allow',
              Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/POST/authorizer-test',
            },
            {
              Action: 'execute-api:Invoke',
              Effect: 'Allow',
              Resource: 'arn:aws:execute-api:us-east-1:random-account-id:random-api-id/local/POST/authorizer-test/*',
            },
          ],
        },
      });
    });
    it('throws error with missing principalId', () => {
      expect(() => {
        generatePolicy();
      }).toThrow('Missing principalId to generate policy');
    });
    it('throws error with missing effect', () => {
      expect(() => {
        generatePolicy('principalId');
      }).toThrow('Missing effect to generate policy');
    });
    it('throws error with missing resource', () => {
      expect(() => {
        generatePolicy('principalId', 'Allow');
      }).toThrow('Missing resource to generate policy');
    });
  });

  describe('getPrincipalId', () => {
    it('returns user by default', () => {
      expect(getPrincipalId()).toEqual('user');
      expect(getPrincipalId({
        hooks: {
          generatePrincipalId: () => {},
        },
      })).toEqual('user');
    });
    it('returns value returned from hook', () => {
      expect(getPrincipalId({
        hooks: {
          generatePrincipalId: () => 'differentuser',
        },
      })).toEqual('differentuser');
    });
  });

  describe('defaultGeneratePrincipalId', () => {
    expect(defaultGeneratePrincipalId()).toEqual('user');
  });

  describe('defaultPostPolicyGeneration', () => {
    it('returns policy as provided', async () => {
      const policy = await defaultPostPolicyGeneration({
        policy: {
          testPolicy: true,
        },
      });
      expect(policy).toEqual({ testPolicy: true });
    });
  });
});
