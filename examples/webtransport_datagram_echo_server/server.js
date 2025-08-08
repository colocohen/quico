var quico = require('../../index');  // או './index' אם אתה מריץ מהשורש
var fs = require('fs');

var server = quico.createServer({
  SNICallback: function (servername, cb) {
    console.log('Getting certificate for:', servername);
    cb(null, {
      key: fs.readFileSync('certs/localhost.key'),
      cert: fs.readFileSync('certs/localhost.crt')
    });
  }
});

server.on('webtransport', function(session) {
  console.log('WebTransport session opened');

  session.ondatagram = function(data) {
    console.log('Datagram from client:', Buffer.from(data).toString());
    session.send(data);
  };

  session.onclose = function() {
    console.log('WebTransport session closed');
  };
});

server.listen(4433, function() {
  console.log('QUIC server running on port 4433');
});