// DOM XSS — innerHTML sink with user-controlled data.

function renderMessage() {
  const params = new URLSearchParams(window.location.search);
  const msg = params.get("message");
  document.getElementById("msg").innerHTML = msg;
}

// Also bad: document.write + eval
document.write("<p>Hello " + msg + "</p>");
eval(params.get("code"));
