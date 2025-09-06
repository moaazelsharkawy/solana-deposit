// ecosystem.config.js
module.exports = {
  apps: [
    {
      name: 'solana-deposit',
      script: 'server.js',
      args: '',
      instances: 1,               // ابدأ بواحد؛ لاحقًا يمكن زيادتها مع تعديل pool size
      exec_mode: 'fork',          // استخدم 'cluster' فقط إذا ضبطت sticky sessions و pool size
      watch: false,               // لا تفعيل المراقبة التلقائية للتغييرات في الإنتاج
      autorestart: true,
      restart_delay: 3000,        // إعادة التشغيل بعد 3 ثواني إذا توقف التطبيق
      max_restarts: 10,
      env: {
        NODE_ENV: 'development'
        // يمكن إضافة متغيرات dev إضافية هنا
      },
      env_production: {
        NODE_ENV: 'production'
        // لا تضع أسرار هنا، استخدم .env أو متغيرات نظامية لـ PM2
      }
    }
  ]
};
