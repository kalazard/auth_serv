<?php

/**
 * Déclaration d'une classe qui contiendra les méthodes de Service WEB, et instanciation de la classe SoapServer
 * pour rendre notre Service disponible
 *
 */
class Utilisateur {

    function logUserIn($username, $password) {

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
            if($donnes = $reponse->fetch())
            {
                //L'utilisateur est connecté, on renvoie son id
                return array("connected" => true, "userid" => $donnes["id"]);
            }
            else
            {
                return array("connected" => false);
            }
        } else {
            return array("connected" => false);
        }
    }
    
    function createUser($username, $password)
    {
        $bdd = new PDO('mysql:host=130.79.214.167;dbname=auth_serv;charset=utf8', 'grp6_access', 'apz37_tA2x');
        $reponse = $bdd->prepare("INSERT INTO utilisateur (email,mdp,salage) VALUES(:email,:mdp,:salage)");
        $reponse->bindValue(':email', $username, PDO::PARAM_STR);
        $salage = md5(uniqid('', true));
        $reponse->bindValue(':mdp', hash('sha512', '#' . $password . "#" . $salage), PDO::PARAM_STR);
        $reponse->bindValue(':salage', $salage, PDO::PARAM_STR);
        $reponse->execute();
    }

}

try {
    $server = new SoapServer(null, array('uri' => 'http://localhost/auth_serv/index.php'));

    $server->setClass("Utilisateur");
    $server->handle();
} catch (Exception $e) {
    echo "Exception: " . $e;
}

