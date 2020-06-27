<?php namespace BNLambert\Phalcon\Auth;

use BNLambert\Phalcon\Auth\Interfaces\AuthInterface;
use BNLambert\Phalcon\Auth\Helpers\Session;
use BNLambert\Phalcon\Auth\Helpers\Cookies;
use BNLambert\Phalcon\Auth\Traits\DBQuery;
use Phalcon\Security;
use Phalcon\Loader;
use Phalcon\Di\Injectable;

/**
*  A Auth class
*
*  Implementation of  auth methods
*
*  @author BN Lambert
*/
class Auth  extends Injectable implements AuthInterface {
    use DBQuery;

    protected  $sessionManager;
    protected $cookiesManager;
    

    public function __construct()
    {
        $this->sessionManager = new Session();
        $this->cookiesManager = new Cookies();
		    $modelsNamespace = json_decode(json_encode($this->config->auth->modelsNamespace), true);

        // AutoLoad auth models from Phalcon app
        $loader = new Loader();
        $loader->registerNamespaces($modelsNamespace);
        $loader->register();
    }

   /**
   *
   */
   public function check(array $credentials = [], $flags = [])
   {
       $email = $credentials['email'] ?? null;
       $password = $credentials['password'] ?? ' ';
       $rememberMe = $credentials['rememberMe'] ?? false;

       $model = $this->config->auth->userModel;

       $query = $this->makeConditions($this->config->auth->authWith, $credentials, $flags);

       $user = $model::findFirst([
         'conditions' => $query['conditions'],
         'bind' => $query['bindParams']
       ]);

       if (is_object($user)) {
           // Check the password
           $security = new Security();
           if (!$security->checkHash($password, $user->password)) {
               $this->registerUserThrottling($user->id);

               return false;
           }
       }
       else {
           $this->registerUserThrottling(0);
           return false;
       }

       // Register the successful login
       $this->saveSuccessLogin($user);

       

       // Check if the remember me was selected
       if ($rememberMe) {
           $token = $this->cookiesManager->setRememberMe($user, $this->config->auth->cookiesDuration);

           $this->saveUserCookiesToken($user, $token);
           $this->cookiesManager->confirm($user->id);
       }

       $this->sessionManager->register($user);

       return true;
   }


    public function modelName($className)
    {
        $model = $className;
        $parts = explode('\\', $model);
        $partsSize = count($parts);
        $modelName = $parts[$partsSize - 1];

        return $modelName;

    }

    public function saveSuccessLogin($user)
    {
        $model = $this->config->auth->successModel;

        $successLogin = new $model();
        $successLogin->user_id = $user->id;
        $successLogin->ip_address = $this->request->getClientAddress();
        $successLogin->user_agent = $this->request->getUserAgent();
        $successLogin->save();

    }

    public function saveUserCookiesToken($user, $token)
    {
        $model = $this->config->auth->rememberModel;

        $remember = new $model();
        $remember->user_id = $user->id;
        $remember->token = $token;
        $remember->user_agent = $this->request->getUserAgent();
        $remember->ip_address = $this->request->getClientAddress();

        return $remember->save();

    }

    public function registerUserThrottling($userId)
    {
        $model = $this->config->auth->failedModel;

        $failedLogin = new $model();
        $failedLogin->user_id = $userId;
        $failedLogin->user_agent = $this->request->getUserAgent();
        $failedLogin->ip_address = $this->request->getClientAddress();
        $failedLogin->attempted = time();
        $failedLogin->save();

        $attempts = $model::count([
            'ip_address = ?0 AND attempted >= ?1',
            'bind' => [
                $this->request->getClientAddress(),
                time() - 3600 * 6
            ]
        ]);

        $attempts = 1;

        switch ($attempts) {
            case 1:
            case 2:
                // no delay
                break;
            case 3:
            case 4:
                sleep(2);
                break;
            default:
                sleep(4);
                break;
        }
    }

    public function logout()
    {
        $this->sessionManager->clear();

        if ($this->cookiesManager->hasToken()) {
            $token = $this->cookiesManager->getToken();
            $user = $this->getUserToken($token);
            if ($user) {
                $user->delete();
            }
            $this->cookiesManager->forget();
            $this->user = null;
        }
    }

    public function guard()
    {
        $user = $this->sessionManager->getUser();

        if (!is_object($user)) {

            $this->response->redirect($this->config->auth->loginPath);

            return false;
        }



    }

    public function getUserToken($token)
    {
        $model = $this->config->rememberModel;

        $userToken = $model::findFirst([
            'conditions' => 'token = :token:',
            'bind'       => [
                'token' => $token
            ]
        ]);

        return $userToken;
    }

    public function checkSession()
    {
        $user = $this->sessionManager->getUser();

        if (is_object($user)) {
            return $this->response->redirect($this->config->auth->redirectTo);
        }
        else {
            $params = $this->cookiesManager->getSessionParams();

            if (is_array($params)) {
                $userToken = $this->getUserToken($params['token']);

                if($params['token'] == $userToken->token && $this->cookiesManager->hasExpired($userToken->created_at, $this->config->cookiesDuration)) {
                    $model = $this->config->auth->userModel;
                    $user = $model::findFirst($params['userId']);
                    $this->saveSuccessLogin($user);
                    $this->sessionManager->register($user);
                    $this->user = $user;

                    // redirect to intended / default path
                    $this->response->redirect($this->config->auth->redirectTo);
                    return false;
                }
                else {

                    $this->cookiesManager->forget();
                }
            }


        }

    }

    public function user()
    {
        return $this->sessionManager->getUser();
    }

}
