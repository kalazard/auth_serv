<?php

/**
 * Déclaration d'une classe qui contiendra les méthodes de Service WEB, et instanciation de la classe SoapServer
 * pour rendre notre Service disponible
 *
 */
class Utilisateur {

    private $know_host = array("127.0.0.1", "130.79.214.167"); //les serveurs connus qui sont autorisés sur ce serveur
    private $public_key = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcMD35gu6ZRORC5fSUTXXXZyGI
67fBjkdSUvDlyLGuAs6ClnVUOb4yXJtFXCSeN5j+0VrFdNVZOpG6lxbdhKixrvTl
YLnKZ6qTdC4gWPOx7nf8VjqCP4VRCLIdvwtMy55vgFDuAQYWXD6dach6LlIt/O4O
vfhOfpzYH4v9xyYjuwIDAQAB
-----END PUBLIC KEY-----";
    private $private_key = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCcMD35gu6ZRORC5fSUTXXXZyGI67fBjkdSUvDlyLGuAs6ClnVU
Ob4yXJtFXCSeN5j+0VrFdNVZOpG6lxbdhKixrvTlYLnKZ6qTdC4gWPOx7nf8VjqC
P4VRCLIdvwtMy55vgFDuAQYWXD6dach6LlIt/O4OvfhOfpzYH4v9xyYjuwIDAQAB
AoGAAj4bFbMQk/jOQjulCGAYWhBsBdhEmi3dzkvMk7APBQ2bQ3q/kocFuRllTVim
WfM4aig9YmpsCczyfLhgpquZ9HVtj686RGqB8iN7Sdm5Pzo5kGrcHdNjuh3wnlAq
NncGRdKI/GoSV4ujbv6pF2Ftlg0sDA5JRqwniUy5ZLpm4EkCQQDJxGCRexnfutxL
9VsgvsS79iNScPUeQXlViF9HtF7PmMZvwjYwET4Pq7ekRz2qE4qpjQ52KpMxsfSq
XH5hTjv3AkEAxiuXXdAPz2MpTWBmRT0Z9RSUnVnS6MzRiIXmhEFEKPtdNvgD+Y7u
EYthQc8IJDhAF8Xeuj8wKk9sgCarQPO9XQJBALBodlY8Xz7xzbLL7sUOhkwgxHlM
McQmUsOp3ESBO3Qei0EjeOVF7hEdfg6wCwYs18uufLpsNw34HYbmH8lL8bkCQCPx
nife6C82jjRBquseFQo17GrJ8w5UsCCyIMiWSfWg+hxRSe9G9HlsLXzRP2nKZh2p
vydK9MKH22c3HFLQouUCQEF7UNyktq3T0B52sz9Je4mpli4GgplIcHC90+zE6+sq
0hlMdGjelZ73Yd8zPuhxVTEW8QgkTUOE61069HpgaVQ=
-----END RSA PRIVATE KEY-----";

    function logUserIn($username, $password, $server) {

        try {
            //Si le client ne peut pas accéder à ce serveur
            $username = $this->decrypt($username);
            $password = $this->decrypt($password);
            $server = $this->decrypt($server);

            if (!$this->check_server_identity($server)) {
                throw new Exception("Ce serveur n'est pas autorisé", 500);
            }

            $bdd = new PDO('mysql:host=130.79.214.167;dbname=auth_serv;charset=utf8', 'grp6_access', 'apz37_tA2x');
            $reponse = $bdd->prepare("SELECT * FROM utilisateur where email=:email");
            $reponse->bindValue(':email', $username, PDO::PARAM_STR);
            $reponse->execute();

            if ($donnes = $reponse->fetch()) {
                //On a récupéré l'utilisateur avec son email. Maintenant on va regarder si il est connecté
                //On a la clé de salage
                $salage = $donnes["salage"];
                //Le mot de passe qu'il faudra vérifier dans la base de données
                $password_to_check = hash('sha512', '#' . $password . "#" . $salage);
                $reponse = $bdd->prepare("SELECT * FROM utilisateur where email=:email AND mdp=:mdp");
                $reponse->bindValue(':email', $username, PDO::PARAM_STR);
                $reponse->bindValue(':mdp', $password_to_check, PDO::PARAM_STR);
                $reponse->execute();
                if ($donnes = $reponse->fetch()) {
                    if ($donnes["actif"] == 1) {
                        //L'utilisateur est connecté, on renvoie son id
                        return array("connected" => true, "userid" => $this->encrypt($donnes["id"]));
                    } else {
                        return array("connected" => false, "message" => "Le compte est inactif");
                    }
                } else {
                    return array("connected" => false, "message" => "Le mot de passe est incorrect");
                }
            } else {
                return array("connected" => false, "message" => "Le nom d'utilisateur est incorrect");
            }
        } catch (Exception $exc) {
            return array("connected" => false, "message" => "erreur du serveur" . $exc->getMessage());
        }
    }

    function createUser($username, $password, $server) {
        try {
            //Si le client ne peut pas accéder à ce serveur

            $username = $this->decrypt($username);
            $password = $this->decrypt($password);
            $server = $this->decrypt($server);

            if (!$this->check_server_identity($server)) {
                throw new Exception("Ce serveur n'est pas autorisé", 500);
            }
            $bdd = new PDO('mysql:host=130.79.214.167;dbname=auth_serv;charset=utf8', 'grp6_access', 'apz37_tA2x');
            $reponse = $bdd->prepare("INSERT INTO utilisateur (email,mdp,salage, actif) VALUES(:email,:mdp,:salage,1)");

            $reponse->bindValue(':email', $username, PDO::PARAM_STR);
            $salage = md5(uniqid('', true));
            $reponse->bindValue(':mdp', hash('sha512', '#' . $password . "#" . $salage), PDO::PARAM_STR);
            $reponse->bindValue(':salage', $salage, PDO::PARAM_STR);
            $reponse->execute();
            return array("error" => false, 'id_user' => $this->encrypt($bdd->lastInsertId()));
        } catch (Exception $exc) {
            return array("error" => true, "message" => $exc->getMessage());
        }
    }

    function updateUser($id, $email, $server) {
        try {
            //Si le client ne peut pas accéder à ce serveur

            $id = $this->decrypt($id);
            $email = $this->decrypt($email);
            $server = $this->decrypt($server);

            if (!$this->check_server_identity($server)) {
                throw new Exception("Ce serveur n'est pas autorisé", 500);
            }
            $bdd = new PDO('mysql:host=130.79.214.167;dbname=auth_serv;charset=utf8', 'grp6_access', 'apz37_tA2x');
            $reponse = $bdd->prepare("UPDATE utilisateur SET email=:email WHERE id=:id");

            $reponse->bindValue(':email', $email, PDO::PARAM_STR);
            $reponse->bindValue(':id', $id, PDO::PARAM_INT);

            $reponse->execute();
            return array("error" => false);
        } catch (Exception $exc) {
            return array("error" => true, "message" => $exc->getMessage());
        }
    }

    function updateUserActivation($id, $activation, $server) {
        try {
            //Si le client ne peut pas accéder à ce serveur

            $id = $this->decrypt($id);
            $activation = $this->decrypt($activation);
            $server = $this->decrypt($server);

            if (!$this->check_server_identity($server)) {
                throw new Exception("Ce serveur n'est pas autorisé", 500);
            }
            $bdd = new PDO('mysql:host=130.79.214.167;dbname=auth_serv;charset=utf8', 'grp6_access', 'apz37_tA2x');
            $reponse = $bdd->prepare("UPDATE utilisateur SET actif=:activation WHERE id=:id");

            $reponse->bindValue(':activation', $activation, PDO::PARAM_INT);
            $reponse->bindValue(':id', $id, PDO::PARAM_INT);

            $reponse->execute();
            return array("error" => false);
        } catch (Exception $exc) {
            return array("error" => true, "message" => $exc->getMessage());
        }
    }

    function getUserActivation($id, $server) {
        try {
            //Si le client ne peut pas accéder à ce serveur
            $id = $this->decrypt($id);
            $server = $this->decrypt($server);

            if (!$this->check_server_identity($server)) {
                throw new Exception("Ce serveur n'est pas autorisé", 500);
            }
            $bdd = new PDO('mysql:host=130.79.214.167;dbname=auth_serv;charset=utf8', 'grp6_access', 'apz37_tA2x');
            $reponse = $bdd->prepare("SELECT actif from utilisateur where id=:id");
            $reponse->bindValue(':id', $id, PDO::PARAM_INT);
            $reponse->execute();
            if ($donnes = $reponse->fetch()) {
                if ($donnes["actif"] == 1) {
                    return array("error" => false, 'actif' => '1');
                } else {
                    return array("error" => false, 'actif' => '0');
                }
            }

            return array("error" => false);
        } catch (Exception $exc) {
            return array("error" => true, "message" => $exc->getMessage());
        }
    }

    public function changePassword($id, $newpassword, $server) {
        try {
            //Si le client ne peut pas accéder à ce serveur

            $id = $this->decrypt($id);
            $newpassword = $this->decrypt($newpassword);
            $server = $this->decrypt($server);

            if (!$this->check_server_identity($server)) {
                throw new Exception("Ce serveur n'est pas autorisé", 500);
            }

            $bdd = new PDO('mysql:host=130.79.214.167;dbname=auth_serv;charset=utf8', 'grp6_access', 'apz37_tA2x');
            $reponse = $bdd->prepare("SELECT salage FROM utilisateur where id=:id");
            $reponse->bindValue(':id', $id, PDO::PARAM_INT);
            $reponse->execute();

            if ($donnes = $reponse->fetch()) {
                //On a récupéré l'utilisateur avec son email. Maintenant on va regarder si il est connecté
                //On a la clé de salage
                $salage = $donnes["salage"];
                //Le mot de passe qu'il faudra vérifier dans la base de données
                $reponse = $bdd->prepare("UPDATE utilisateur SET mdp=:mdp WHERE id=:id");

                $reponse->bindValue(':mdp', hash('sha512', '#' . $newpassword . "#" . $salage), PDO::PARAM_STR);
                $reponse->bindValue(':id', $id, PDO::PARAM_INT);

                $reponse->execute();
            } else {
                return array("error" => true, "message" => "Impossible de modifier le mot de passe de cet utilisateur");
            }

            return array("error" => false);
        } catch (Exception $exc) {
            return array("error" => true, "message" => $exc->getMessage());
        }
    }

    //Fonction qui servira a crypter les données
    private function encrypt($data) {
        if (openssl_public_encrypt($data, $encrypted, $this->public_key))
            return base64_encode($encrypted);
        else
            return false;
    }

    //Fonction qui servira a decrypter les données
    private function decrypt($data) {
        if (openssl_private_decrypt(base64_decode($data), $decrypted, $this->private_key))
            return $decrypted;
        else
            return false;
    }

    //Permettra de connaître l'identité du serveur emetteur de la requête
    private function check_server_identity($server) {
        $senderHost = $server;
        //On vérifie que le serveur emetteur a l'accès à ce serveur
        if (in_array($senderHost, $this->know_host)) {
            return true;
        } else {
            return false;
        }
    }

}

try {
    $server = new SoapServer(null, array('uri' => 'http://localhost/auth_serv/index.php'));
    $server->setClass("Utilisateur");
    $server->handle();
} catch (Exception $e) {
    echo "Exception: " . $e;
}

