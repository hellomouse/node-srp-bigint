module.exports = {
  extends: [
    'eslint:recommended',
    'eslint-config-google',
  ],
  parser: 'babel-eslint',
  parserOptions: {
    ecmaVersion: 9,
    sourceType: 'module',
    ecmaFeatures: {
      experimentalObjectRestSpread: true
    }
  },
  plugins: ['babel'],
  env: {
    es6: true,
    node: true
  },
  globals: {
    BigInt: 'readonly'
  },
  rules: {
    'prefer-const': 'off',
    'comma-dangle': 'off',
    'arrow-parens': ['error', 'as-needed'],
    'indent': 'off',
    'no-console': 'off',
    'object-curly-spacing': ['error', 'always'],
    'space-infix-ops': ['error', { int32Hint: true }],
    'max-len': ['error', 120],
    'new-cap': ['error', { 'capIsNewExceptions': ['BigInt'] }],

    // babel-eslint override rules
    'valid-typeof': 'off',
    'babel/valid-typeof': 'error',
  }
};
