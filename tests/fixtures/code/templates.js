// Template injection fixtures.

// template-handlebars-compile-user
const tpl = Handlebars.compile(req.body.template);

// template-pug-user-input
const out = pug.render(req.query.src, { locals: {} });
const compiled = pug.compile(req.body.template);
