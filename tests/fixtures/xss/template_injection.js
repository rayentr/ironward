// Template injection — EJS <%- %> unescaped + Handlebars triple-brace.

const ejs = require("ejs");
const Handlebars = require("handlebars");

const ejsTemplate = `
  <div>Welcome, <%- username %></div>
`;

const hbsTemplate = `
  <section>{{{ rawBio }}}</section>
`;

function renderProfile(user) {
  const html1 = ejs.render(ejsTemplate, { username: user.name });
  const html2 = Handlebars.compile(hbsTemplate)({ rawBio: user.bio });
  return html1 + html2;
}
