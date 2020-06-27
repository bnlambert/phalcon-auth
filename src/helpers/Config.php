<?php
/**
 * Created by IntelliJ IDEA.
 * User: HP
 * Date: 12/22/2019
 * Time: 9:58 PM
 */

namespace BNLambert\Phalcon\Auth\helpers;

use Phalcon\Di\Injectable;

class Config extends Injectable
{
    public $userModel;
    public $successModel;
    public $failedModel;
    public $cookiesDuration;
    public $rememberModel;
    public $redirectTo;
    public $redirectToIntended;
    public $modelsNamespace;

    public function __construct()
    {
		$params = $this->config->auth;
		
        $this->modelsNamespace = $params['modelsNamespace'] ?? ['/models'];
        $this->userModel = $params['userModel'] ?? null;
        $this->successModel = $params['successModel'] ?? null;
        $this->failedModel = $params['failedModel'] ?? null;
        $this->rememberModel = $params['rememberModel'] ?? null;
        $this->cookiesDuration = $params['cookiesDuration'] ?? time() + (86400 * 8);
    }

    public function setUserModel($model)
    {
        $this->userModel = $model;
    }
}