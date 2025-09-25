const app = require("./app.js");

const PORT = 3000;
//const NODE_ENV = 'development';

// Start server
const server = app.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log(`Server running on: http://localhost:${PORT}`);
    console.log('='.repeat(50));
});

// Handle server errors
server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
    } else {
        console.error('❌ Server error:', error);
    }
    process.exit(1);
});