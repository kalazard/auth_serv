<?php
/**
 * Déclaration d'une classe qui contiendra les méthodes de Service WEB, et instanciation de la classe SoapServer
 * pour rendre notre Service disponible
 *
 */
class Utilisateur
{
  function get($i)
  {
    return $i;
  }
  function hello()
  {
    return "hello world";
  }
}

try
{
  $server = new SoapServer(null, array('uri' => 'http://localhost/auth_serv/index.php'));

  $server->setClass("Utilisateur");
  $server->handle();
}
catch(Exception $e)
{
  echo "Exception: " . $e;
}

