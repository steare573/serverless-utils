
import promisify from 'util.promisify';
import debug from 'debug';
import jwt from 'jsonwebtoken';
import {
  getAccessToken,
  extractJwtData,
  generateJwksClient,
  generatePolicy,
  getPrincipalId,
} from './util';

jwt.verifyAsync = promisify(jwt.verify);
const log = debug('aws-authorizer-oidc:authorize');

const authorize = async (config, event, context) => {
  const {
    methodsApplied,
    acceptedScopes,
    jwtIssuer,
    jwtAudiences,
    jwtSigningAlgorithms,
    pathMapping,
    hooks,
  } = config;
  let accessToken;
  try {
    accessToken = getAccessToken(event);
  } catch (e) {
    log(`Unauthorized(Invalid access token): ${e.message}`);
    throw e;
  }
  const jwtObject = extractJwtData(accessToken);

  const jwksClient = generateJwksClient(config);
  let key;
  try {
    const keyObj = await jwksClient.getSigningKeyAsync(jwtObject.kid);
    key = keyObj.publicKey || keyObj.rsaPublicKey;
  } catch (err) {
    log(`Unauthorized(Signature Key Retrieval Error): ${err}`);
    throw err;
  }

  try {
    await jwt.verify(
      accessToken,
      key,
      {
        issuer: jwtIssuer,
        audience: jwtAudiences,
        algorithms: jwtSigningAlgorithms,
      },
    );
  } catch (err) {
    log(`Error Unauthorized(JWT verification error): ${err.message} ${config.jwtIssuer}`);
    throw err;
  }
  log('Accepted scopes %o', acceptedScopes);
  log('Actual scopes: %o', jwtObject.scopes);
  let policy;
  if (acceptedScopes.some(scope => jwtObject.scopes.indexOf(scope) !== -1)) {
    log('Scope found.  Allow access');
    policy = generatePolicy(getPrincipalId(config, jwtObject), 'Allow', event.methodArn, methodsApplied, pathMapping);
  } else {
    log('Scope not found.  Deny access');
    policy = generatePolicy(getPrincipalId(config, jwtObject), 'Deny', event.methodArn, methodsApplied, pathMapping);
  }

  log('Generated policy: %o', policy);
  log('Statements: %o', policy.policyDocument.Statement);

  if (hooks.postPolicyGeneration) {
    log('Post policy hook executing');
    // this hook needs to be a promise/async function
    policy = await hooks.postPolicyGeneration({
      event,
      context,
      policy,
      decodedJwt: jwtObject,
      config,
    });
  }

  return policy;
};

export default authorize;
