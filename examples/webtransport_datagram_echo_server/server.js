import quico from 'quico';
import fs from 'node:fs';
import tls from 'lemon-tls';

var server = quico.createServer({
  SNICallback: function (servername, cb) {
    console.log('Getting certificate for:', servername);
    cb(null, tls.createSecureContext({
      key: fs.readFileSync('./certs/localhost2.key'),
      cert: fs.readFileSync('./certs/localhost2.crt')
    }));
  }
},function(req,res){
  if (req.headers[':protocol'] === 'webtransport') {
    res.writeHead(200);

    //TODO
  }
});

server.listen(4433, function() {
  console.log('QUIC server running on port 4433');
});