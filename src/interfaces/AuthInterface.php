<?php
namespace BNLambert\Phalcon\Auth\Interfaces;
/**
 * Created by IntelliJ IDEA.
 * User: HP
 * Date: 12/22/2019
 * Time: 9:04 PM
 */

interface AuthInterface {
    public function check(array $credentials = [], $flag = []);

   //  public function loginUser($userId);

   //  public function user();

    // public function checkRememberMe();

    // public function guard($dispatcher, $except = []);
}