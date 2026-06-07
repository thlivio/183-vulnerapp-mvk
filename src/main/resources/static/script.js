// globals (yay vanilla javascript ftw)
fetchBlogs();
loginCheck();
document.getElementById("login-form")
    .addEventListener("submit", onLoginSubmit);
document.getElementById("logout-form")
    .addEventListener("submit", onLogoutSubmit);
document.getElementById("blog-form")
    .addEventListener("submit", onBlogSubmit);
let devToast = new bootstrap.Toast(
    document.getElementById("devToast"),
    { delay: 10000 }
);

function onLoginSubmit(event) {
  const username = event.target[0].value;
  const password = event.target[1].value;
  event.preventDefault();
  // fetch CSRF token (server exposes /api/csrf) then perform login
  getCsrfToken().then(token => {
    return fetch("/login", {
      method: "POST",
      credentials: 'include',
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        [token.headerName]: token.token
      },
      body: new URLSearchParams({username, password}),
    });
  })
  .then(filterOk)
  .then(response => response.json())
  .then(user => window.sessionStorage.setItem("fullname", user.fullname))
  .then(() => loginCheck());
}

function onLogoutSubmit(event) {
  event.preventDefault();
  getCsrfToken().then(token => fetch('/api/logout', {
    method: 'POST',
    credentials: 'include',
    headers: { [token.headerName]: token.token }
  })).finally(() => {
    window.sessionStorage.removeItem("fullname");
    loginCheck();
  });
}

function onBlogSubmit(event) {
  const data = {"title": event.target[0].value, "body": event.target[1].value};
  event.preventDefault();
  getCsrfToken().then(token => fetch("/api/blog", {
    method: "POST",
    credentials: 'include',
    headers: {
      "Content-Type": "application/json",
      [token.headerName]: token.token
    },
    body: JSON.stringify(data),
  }))
      .then(filterOk)
      .then(() => fetchBlogs())
      .then(() => event.target.reset());
}


function getCsrfToken(){
  return fetch('/api/csrf', {credentials: 'include'})
    .then(filterOk)
    .then(res => res.json())
    .then(body => ({ headerName: body.headerName, token: body.token }));
}

function loginCheck() {
  const fullname = window.sessionStorage.getItem("fullname") || "anonymous";
  let authentic = fullname !== "anonymous";
  document.getElementById("login-form").parentElement.hidden = authentic;
  document.getElementById("logout-form").parentElement.hidden = !authentic;
  document.getElementById("username").innerText = fullname;
}

function fetchBlogs() {
  fetch("/api/blog")
      .then(filterOk)
      .then(response => response.json())
      .then(page => renderBlogs(page.content));
}

function renderBlogs(blogs) {
  const blogDiv = document.getElementById("blog-container");
  blogDiv.innerHTML = "" // clear
  for (const blog of blogs) {
    blogDiv.innerHTML += `<h2>${blog.title}</h2>
            <p>${blog.createdAt}</p>
            <p>${blog.body}</p>`;
  }
}

function showDevError(message) {
  document.getElementById("devToastText").textContent = message;
  devToast.show();
}

function filterOk(response) {
  if (response.ok) {
    return response;
  }
  return response.text().then(function(bodyText) {
    let msg = `HTTP ${response.status} ${response.statusText}\n${bodyText}`;
    if(msg.length > 1000){
      msg = msg.substring(0, 1000) + "\n...[truncated]";
    }
    showDevError(msg);
    throw response;
  });
}
