const cors = require('cors')

const origin = [
  "https://week-15-mnajmytsss.vercel.app", 
  "https://week-15-mnajmytsss.cyclic.app",
];
const partnerOrigin = [
  "https://week15.avicena.dev",
  "https://week15-defficharlina-fe.vercel.app" 
];

const corsOptionsDelegate = (req, callback) => {
    const clientOrigin = origin.includes(req.header("Origin"));
    const clientPartnerOrigin = partnerOrigin.includes(req.header("Origin"))

    if (clientOrigin) {
        callback(null, {
          origin: true,
          methods: "GET, POST, DELETE, PUT, OPTIONS, HEAD",
        });
      } else if (clientPartnerOrigin) {
        callback(null, {
          origin: true,
          methods: "GET, POST",
        });
      } else {
        callback(new Error("Blocked by CORS"));
      }
};

const corsMiddleware = (app) => {
    app.use(cors());
};

module.exports = corsMiddleware;