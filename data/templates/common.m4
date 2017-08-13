changecom(`@@##')dnl
define(`JSCSS', `dnl
    <script type="text/javascript">
include(`tor2web.min.js')dnl
    </script>
    <style type="text/css">
include(`tor2web.css')dnl
    </style>
')dnl
define(`generate_page', `dnl
<html>
  <head>
    <title>$1</title>
    <meta http-equiv="content-type" content="text/html;charset=utf-8" />
    <meta http-equiv="content-language" content="en" />
    <meta name="robots" content="noindex" />
JSCSS()dnl
  </head>
  <body>
    <div id="tor2web">
      <div id="header">
        <h1><a href="https://www.tor2web.org">dnl
<img src="data:image/png;base64,syscmd(`base64 -w0 < tor2web.png')dnl
" alt="tor2web logo" /></a></h1>
      </div>
      <div id="$2">
$3dnl
      </div>
    </div>
  </body>
</html>
')dnl
