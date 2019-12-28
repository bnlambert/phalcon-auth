<?php namespace BNLambert\Phalcon\Auth;

use BNLambert\Phalcon\Auth\Interfaces\AuthInterface;
use BNLambert\Phalcon\Auth\Helpers\Config;
use BNLambert\Phalcon\Auth\Helpers\Session;
use BNLambert\Phalcon\Auth\Helpers\Cookies;
use Phalcon\Security;
use Phalcon\Loader;
use Phalcon\Http\Response;

use Phalcon\Mvc\Dispatcher;
/**
*  A sample class
*
*  Use this section to define what this class is doing, the PHPDocumentator will use this
*  to automatically generate an API documentation using this information.
*
*  @author yourname
*/
class Auth implements AuthInterface {

    protected $config;
    protected  $session;
    protected $cookies;
    protected $request;
    protected $flash;
    protected $response;
    protected $dispatcher;


    public function __construct($di, $configOptions = [])
    {
        $this->session = new Session($di['session']);
        $this->cookies = new Cookies($di['cookies'], $di['request'], $di['response']);
        $this->request = $di['request'];
        $this->dispatcher = $di['dispatcher'];
        $this->response =  $di['response']; // new Response();
        $this->config = new Config($configOptions);

        // AutoLoad auth models from Phalcon app
        $loader = new Loader();
        $loader->registerNamespaces($this->config->modelsNamespace);
        $loader->register();

        /*
        spl_autoload_register(function ($classname) {
            $filename = APP_PATH . $this->config->modelPath . '/' . $this->modelName($classname) . '.php';
            require_once($filename);
        });
        */


    }

    /**  @var string $m_SampleProperty define here what this variable is for, do this for every instance variable */
   private $m_SampleProperty = '';
 
  /**
  * Sample method 
  *
  * Always create a corresponding docblock for each method, describing what it is for,
  * this helps the phpdocumentator to properly generator the documentation
  *
  * @param string $param1 A string containing the parameter, do this for each parameter to the function, make sure to make it descriptive
  *
  * @return string
  */
   public function method1($param1){
			return "Hello Sam!";
   }

   public function check(array $credentials = [], $flag =[])
   {
       $email = $credentials['email'] ?? null;
       $password = $credentials['password'] ?? ' ';

       $model = $this->config->userModel;

       $user = $model::findFirst("email='$email' AND status = 0");

       // from here

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



       // Check if the user was flagged
       // $this->checkUserFlags($user);

       // Register the successful login
       $this->saveSuccessLogin($user);

       // Check if the remember me was selected
       if (isset($credentials['rememberMe']) && $credentials['rememberMe'] == true) {
           $token = $this->cookies->setRememberMe($user, $this->config->cookiesDuration);

           $this->saveUserCookiesToken($user, $token);
           $this->cookies->confirm($user->id);

           /*
           if($this->saveUserCookiesToken($user, $token)) {
               $this->cookies->confirm($user->id);
           }
           */
       }

       $this->session->register($user);

       // return ['error' => 'none'];

       // return true or redirect
       return $user;
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
        $model = $this->config->successModel;

        $successLogin = new $model();
        $successLogin->user_id = $user->id;
        $successLogin->ip_address = $this->request->getClientAddress();
        $successLogin->user_agent = $this->request->getUserAgent();
        $successLogin->save();

    }

    public function saveUserCookiesToken($user, $token)
    {
        $model = $this->config->rememberModel;

        $remember = new $model();
        $remember->user_id = $user->id;
        $remember->token = $token;
        $remember->user_agent = $this->request->getUserAgent();
        $remember->ip_address = $this->request->getClientAddress();

        return $remember->save();

    }

    public function registerUserThrottling($userId)
    {
        $model = $this->config->failedModel;

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
        $this->session->clear();

        if ($this->cookies->hasToken()) {
            $token = $this->cookies->getToken();
            $user = $this->getUserToken($token);
            if ($user) {
                $user->delete();
            }
            $this->cookies->forget();
        }
    }

    public function guard()
    {
        $user = $this->session->getUser();

        if (!is_object($user)) {

            $this->response->redirect('/auth');

            return false;
        }



    }

    public function alc()
    {

    }

    public function getUserToken($token)
    {
        $model = $this->config->rememberModel;

        $user = $model::findFirst([
            'conditions' => 'token = :token:',
            'bind'       => [
                'token' => $token
            ]
        ]);

        return $user;
    }

    public function checkSession()
    {
        $user = $this->session->getUser();

        if (is_object($user)) {
            return $this->response->redirect('/account');
        }
        else {
            $params = $this->cookies->getSessionParams();

            if (is_array($params)) {
                $userToken = $this->getUserToken($params['token']);

                if($params['token'] == $userToken->token && $this->cookies->hasExpired($userToken->created_at, $this->config->cookiesDuration)) {
                    $model = $this->config->userModel;
                    $user = $model::findFirst($params['userId']);
                    $this->saveSuccessLogin($user);
                    $this->session->register($user);


                    // redirect to intended / default path

                    $this->response->redirect('/account');
                    return false;
                }
                else {

                    $this->cookies->forget();
                }
            }


        }

    }

}