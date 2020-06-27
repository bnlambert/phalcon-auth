<?php
namespace BNlambert\Phalcon\Auth\Traits;

Trait DBQuery {
    /**
    *
    *
    **/
    public function makeConditions($authWith, $credentials, $flags)
    {
        $authWithCount = count($authWith);
      	$conditions = '';
      	$conditionsParams = [];
      	unset($credentials['password']);
      	unset($credentials['rememberMe']);
      	$credentialsKeys = array_keys($credentials);

      	if ($authWithCount == 1) {
        		$conditions .= $authWith[0] . ' = :' . $authWith[0] . ':';
        		$conditionsParams[$authWith[0]] = $credentials[$authWith[0]];
      	}

      	if ($authWithCount > 1) {
        		foreach($authWith as $k => $el) {
          			$addOr = $k == 0 ? '(' : ' OR ';
          			$addBracket = $k == ($authWithCount - 1) ? ')' : '';
          			$conditions .= $addOr . $el . ' = :' .$credentialsKeys[0] . ':' .$addBracket;
          			$conditionsParams[$credentialsKeys[0]] = $credentials[$credentialsKeys[0]];
        		}
      	}

        foreach($flags as $k => $flag) {
        		$conditions .= ' AND ' . $k . ' = :' . $k . ':';
        		$conditionsParams[$k] = $flag;
      	}


      	return [
      		'conditions' => $conditions,
      		'bindParams' => $conditionsParams
      	];
    }
}
?>
