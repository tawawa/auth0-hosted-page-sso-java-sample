<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8"/>
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="/css/bootstrap.css"/>
    <link rel="stylesheet" type="text/css" href="/css/jquery.growl.css"/>
    <script src="http://code.jquery.com/jquery.js"></script>
    <script src="https://cdn.auth0.com/js/lock/10.0/lock.min.js"></script>
    <script src="/js/jquery.growl.js" type="text/javascript"></script>
</head>
<body>
<div class="container">
    <div class="jumbotron">
        <h2 style="text-align: center;">
            <img src="https://cdn.auth0.com/styleguide/1.0.0/img/badge.svg"/>
        </h2>
        <div style="text-align: center;">
            <button id="login-btn" class="btn btn-primary">Login</button>
        </div>
    </div>
</div>
<script type="text/javascript">
  $(function () {
    var error = ${error};
    if (error) {
      $.growl.error({message: "Please log in"});
    } else {
      $.growl({title: "Welcome!", message: "Please log in"});
    }
  });
  $(function () {
    $("#login-btn").click(function () {
      console.log('clicked');
      window.location = 'https://demo-workshop.auth0.com/authorize?client_id=tUkAswnuoi9gfCZBLHvy2ra11ePwhme3&response_type=code&scope=openid profile read:accounts&redirect_uri=http://localhost:3099/callback&nonce=12345&audience=https://resourceapi.com';
    });
  });
</script>
</div>
</body>
</html>
