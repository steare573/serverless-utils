import promisify from 'util.promisify';
import jwt from 'jsonwebtoken';
import debug from 'debug';
import jwks from 'jwks-rsa';

const log = debug('aws-authorizer-oidc:util');
export const DEFAULT_PRINCIPALID = 'user';

/**
 * Generate principalId to be attached to the auth policy
 *
 * @param {Object} config
 * @param {Object} decodedToken
 *
 * @return {string|number}
 */
export const getPrincipalId = (config = {}, decodedToken = {}) => {
  if (config.hooks && config.hooks.generatePrincipalId) {
    return config.hooks.generatePrincipalId(config, decodedToken) || DEFAULT_PRINCIPALID;
  }
  return DEFAULT_PRINCIPALID;
};

/**
 * Default postPolicyGeneration hook to simply forward the generated policy.
 *
 * @param {Object} input
 * @param {Function} cb
 */
export const defaultPostPolicyGeneration = async input => input.policy;

/**
 * Default generate principalId hook that just returns the default value.
 */
export const defaultGeneratePrincipalId = () => DEFAULT_PRINCIPALID;
/**
 * Generate a statement when appliedMethods is passed in rather than pathMapping
 *
 * @param {} methodsApplied
 * @param {*} splitResource
 * @param {*} splitArn
 */
export const generateStatementsWithoutMapping = (methodsApplied, effect, resourceArr, arnArr) => {
  const statements = [];
  const splitResource = Array.from(resourceArr).slice(0, 4);
  const splitArn = Array.from(arnArr);
  methodsApplied.forEach((method) => {
    splitResource[2] = method.toUpperCase();
    splitArn[5] = splitResource.join('/');
    const reconstructedArn = splitArn.join(':');
    statements.push({
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: reconstructedArn,
    });
    statements.push({
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: `${reconstructedArn}/*`,
    });
  });
  return statements;
};

/**
 * Generate a statement based on the path mapping supplied by the user.
 *
 * @param {} pathMapping
 */
export const generateStatementsWithMapping = (pathMapping, effect, resourceArr, arnArr) => {
  const statements = [];
  const splitResource = Array.from(resourceArr.slice(0, 3));
  const splitArn = Array.from(arnArr);
  Object.keys(pathMapping).forEach((method) => {
    pathMapping[method].forEach((route) => {
      splitResource[2] = method.toUpperCase();
      splitResource[3] = route;
      splitArn[5] = splitResource.join('/');
      const reconstructedArn = splitArn.join(':');
      statements.push({
        Action: 'execute-api:Invoke',
        Effect: effect,
        Resource: reconstructedArn,
      });
    });
  });

  return statements;
};

/**
 * Generate aws statements (including ARNs) to be attached to the policy returned by authorizer.
 *
 * @param {*} effect
 * @param {*} resource
 * @param {*} methodsApplied
 * @return {Array}
 */
export const generateStatements = (effect, resource, methodsApplied = [], pathMapping) => {
  if (!effect) throw new Error('Missing effect to generate policy statements');
  if (!resource) throw new Error('Missing resource to generate policy statements');

  const splitArn = resource.split(':');
  const splitResource = splitArn[5].split('/');

  if (!pathMapping || !Object.keys(pathMapping).length) {
    return generateStatementsWithoutMapping(methodsApplied, effect, splitResource, splitArn);
  }

  return generateStatementsWithMapping(pathMapping, effect, splitResource, splitArn);
};

/**
 * Generate aws policy to be returned from authorizer to determine if user is allowed or denied.
 *
 * @param {*} principalId
 * @param {*} effect
 * @param {*} resource
 * @param {*} methodsApplied
 * @return {Object}
 */
export const generatePolicy = (principalId, effect, resource, methodsApplied = [], pathMapping) => {
  if (!principalId) throw new Error('Missing principalId to generate policy');
  if (!effect) throw new Error('Missing effect to generate policy');
  if (!resource) throw new Error('Missing resource to generate policy');
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: generateStatements(effect, resource, methodsApplied, pathMapping),
    },
  };
};

/**
 * Normalize configuration by merging user supplied values, environment variables, and defaults.
 *
 * @param {Object} config
 * @return {Object}
 */
export const normalizeConfig = (config = {}) => {
  const defaultConfig = {
    jwksUri: process.env.AUTHORIZER_JWKS_URI,
    jwtAudiences: process.env.AUTHORIZER_ACCEPTED_AUDIENCES
      ? process.env.AUTHORIZER_ACCEPTED_AUDIENCES.split(',').map(el => el.trim())
      : undefined,
    jwtSigningAlgorithms: process.env.AUTHORIZER_SIGNING_ALGORITHMS
      ? process.env.AUTHORIZER_SIGNING_ALGORITHMS.split(',').map(el => el.trim())
      : ['RS256'],
    jwtIssuer: process.env.AUTHORIZER_ACCEPTED_ISSUER,
    customClaimNamespace: process.env.AUTHORIZER_CUSTOM_CLAIM_NAMESPACE,
    methodsApplied: [],
    acceptedScopes: [],
    pathMapping: {},
    hooks: {
      generatePrincipalId: defaultGeneratePrincipalId,
      postPolicyGeneration: defaultPostPolicyGeneration,
    },
  };
  log('Default config: %o', defaultConfig);

  const mergedHooks = config.hooks
    ? { ...defaultConfig.hooks, ...config.hooks }
    : defaultConfig.hooks;

  return {
    ...defaultConfig,
    ...config,
    ...{
      hooks: mergedHooks,
    },
  };
};

/**
 * Validate configuration object after user, env var, and default configurations have been merged.
 *
 * @param {Object} config
 * @return {boolean}
 * @throws
 */
export const validateConfig = (config) => {
  // TODO: Implement validation
  if (!config) throw new Error('Config must be an object');
  const { methodsApplied, pathMapping } = config;
  if (
    (!methodsApplied || !methodsApplied.length)
    && (!pathMapping || !Object.keys(pathMapping).length)
  ) {
    throw new Error('Must supply either pathMappings or methodsApplied');
  }

  return true;
};

/**
 * Generate jwks client from configuration values passed in.
 *
 * @param {Object} config
 */
export const generateJwksClient = (config) => {
  const client = jwks({
    jwksUri: config.jwksUri,
    rateLimit: config.jwksRateLimit,
    cache: config.jwksUseCache,
    cacheMaxEntries: config.jwksCacheMaxEntries,
    jwksRequestsPerMinute: config.jwksRequestsPerMinute,
    cacheMaxAge: config.jwksCacheMaxAge,
  });

  // promisify signing key retrieval methods.
  client.getSigningKeyAsync = promisify(client.getSigningKey);
  client.getSigningKeysAsync = promisify(client.getSigningKeys);
  client.getKeysAsync = promisify(client.getKeys);

  return client;
};

/**
 * Extract OIDC access token from events with request event types passed into authorizer.
 *
 * @param {Object} event
 * @return {string}
 */
export const getRequestEventAccessToken = (event = {}) => {
  const authHeader = event.headers ? event.headers.Authorization || event.headers.authorization : '';
  log('auth header: %s', authHeader);
  if (!authHeader) {
    throw new Error('No authorization header present');
  }
  log('Event headers: %o', event.headers);
  const authHeaderArray = authHeader.split(' ');
  log('my auth header array %o', authHeaderArray);
  if (!authHeaderArray[0] || authHeaderArray[0].toLowerCase() !== 'bearer') {
    throw new Error('Only bearer tokens supported');
  }

  return authHeaderArray[1];
};

/**
 * Extract OIDC access token from events with token event type passed into authorizer.
 *
 * @param {Object} event
 * @return {string}
 */
export const getTokenEventAccessToken = (event = {}) => {
  if (!event.authorizationToken) {
    throw new Error('No authorization token present');
  }
  log('Event auth token %s', event.authorizationToken);
  const authHeaderArray = event.authorizationToken.split(' ');
  if (authHeaderArray[0].toLowerCase() !== 'bearer') {
    throw new Error('Only bearer tokens supported');
  }

  return authHeaderArray[1];
};

/**
 * Extract OIDC access token from aws event passed into authorizer.
 *
 * @param {Object} event
 * @return {string}
 */
export const getAccessToken = (event) => {
  if (!event) throw new Error('No authorization token present');
  switch (event.type) {
    case 'REQUEST':
      return getRequestEventAccessToken(event);
    case 'TOKEN':
      return getTokenEventAccessToken(event);
    default:
      throw new Error(`Unsupported event type ${event.type}`);
  }
};

/**
 * Decode, extract, and transform jwt data that we are interested in into easily digestable object.
 *
 * @param {string} accessToken
 * @return {Object}
 */
export const extractJwtData = (accessToken) => {
  const decodedJwt = jwt.decode(accessToken, { complete: true });
  if (!decodedJwt) throw new Error('Error parsing jwt token. Token may be malformed');
  const scopeStr = decodedJwt.payload.scope || '';

  return Object.assign({}, decodedJwt.payload, {
    kid: decodedJwt.header.kid,
    scopes: scopeStr.split(' '),
  });
};

export const UNAUTHORIZED = 'Unauthorized';

// Provide all functions as a default export.
export default module.exports;
