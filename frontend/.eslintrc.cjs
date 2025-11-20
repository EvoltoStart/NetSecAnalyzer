// 宽松一点的 Vue3 + JS ESLint 配置
module.exports = {
  root: true,
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  // 先用推荐规则打底，再按需要关掉/放宽
  extends: [
    'eslint:recommended',
    'plugin:vue/vue3-recommended',
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  plugins: ['vue'],
  rules: {
    // ========= JS 相关 =========
    // 允许 console，但给个 warning 提醒一下
    'no-console': 'warn',
    // 同理，允许 debugger，但提示一下
    'no-debugger': 'warn',

    // 允许未使用的函数参数，避免改来改去
    'no-unused-vars': [
      'warn',
      {
        args: 'none', // 函数参数不报错
        ignoreRestSiblings: true,
      },
    ],

    // 不强求 ===，但建议用
    eqeqeq: ['warn', 'smart'],

    // 不强求必须使用分号
    semi: ['off'],

    // 不强制单引号/双引号，交给 Prettier 之类去管也行
    quotes: ['off'],

    // ========= Vue 相关 =========

    // 组件名不强制必须多个单词（例如 Home.vue 允许）
    'vue/multi-word-component-names': 'off',

    // 不强制 props 一定要写详细类型（开发阶段比较轻松）
    'vue/require-default-prop': 'off',
    'vue/require-prop-types': 'off',

    // 允许在模板里用 v-html（有风险但很多安全工具项目会用）
    'vue/no-v-html': 'off',

    // 不强求单文件组件 template 里自闭合标签风格
    'vue/html-self-closing': 'off',

    // 不强制 template 属性顺序
    'vue/attributes-order': 'off',

    // 不强求组件选项顺序
    'vue/order-in-components': 'off',

    // v-for 和 v-if 同时使用时，只给 warning
    'vue/no-use-v-if-with-v-for': 'warn',

    // template 中的 max 行数/复杂度之类的规则先关掉
    'vue/max-attributes-per-line': 'off',
    'vue/singleline-html-element-content-newline': 'off',
    'vue/multiline-html-element-content-newline': 'off',
  },
};
