// NoSQL, LDAP, XXE, template injection, header/log injection fixtures.

// nosql-mongo-where
db.users.find({ $where: "this.name == '" + req.body.name + "'" });

// nosql-mongo-mapreduce
db.users.mapReduce(function () { emit(this.type, 1); }, function (k, v) { return req.body.reducer; }, { out: "out" });

// ldap-filter-user-input
ldap.search(`(uid=${req.body.username})`, (err, res) => {});

// xxe-xml-parser
const p = new DOMParser();
libxmljs.parseXmlString(xmlIn);
xml2js.parseString(xmlIn, (err, r) => {});

// header-injection-crlf
res.setHeader("X-Custom", req.query.value);

// log-injection-user-input
console.log("user logged in: " + req.body.username);
logger.info("event " + req.query.kind);
