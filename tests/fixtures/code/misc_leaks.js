// console.log with secret, commented secret, debugger, TODO auth.

function debugUser(user) {
  console.log("login ok", user.email, user.password);
  console.info("api_key=" + user.apiKey);
  debugger;
}

// OLD_AWS_KEY=AKIATHISISLEFTINCOMMENT12345
// password = "Pr0d@dm1n#2024!"

// TODO: add auth middleware before exposing this route publicly
// FIXME: validate input before inserting into the DB

app.post("/insecure-fetch", async (req, res) => {
  // Plain HTTP in fetch.
  const data = await fetch("http://api.unsafe-provider.com/data");
  res.json(await data.json());
});
