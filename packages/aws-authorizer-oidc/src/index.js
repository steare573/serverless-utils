import debug from 'debug';
import {
  normalizeConfig,
  validateConfig,
  defaultPostPolicyGeneration,
  defaultGeneratePrincipalId,
  UNAUTHORIZED,
} from './util';
import authorize from './authorize';

const log = debug('aws-authorizer-oidc:index');

/**
 * Create a serverless authorizer function based on the configuration passed in.
 *
 * @param {Object} inputConfig
 * @return {Function}
 */
const createAuthorizer = (inputConfig = {}) => {
  const config = normalizeConfig(inputConfig);
  try {
    validateConfig(config);
  } catch (e) {
    throw new Error(`Invalid config: ${e.message}`);
  }

  /* eslint-disable consistent-return */
  return (event, context, cb = () => { }) => {
    authorize(config, event, context)
      .then(policy => cb(undefined, policy))
      .catch((err) => {
        log(`Error: Denying access (${err.message})`);
        cb(UNAUTHORIZED);
      });
  };
};

// expose some common hooks to the user to import and utilize
const hooks = {
  postPolicyGeneration: {
    default: defaultPostPolicyGeneration,
  },
  generatePrincipalId: {
    default: defaultGeneratePrincipalId,
  },
};


export {
  createAuthorizer,
  hooks,
};

export default createAuthorizer;
