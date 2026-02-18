module.exports = {
  apps: [
    {
      name: 'campus-aegis',
      script: 'src/index.js',
      cwd: __dirname,
      node_args: '--enable-source-maps',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: { NODE_ENV: 'development' },
      env_production: { NODE_ENV: 'production', LOG_LEVEL: 'info' },
      error_file: 'logs/err.log',
      out_file: 'logs/out.log',
      merge_logs: true,
      time: true,
    },
  ],
};
