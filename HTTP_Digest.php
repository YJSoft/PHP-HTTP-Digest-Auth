<?php
namespace YJSoft\HTTP;
class HTTP_Digest {
    /**
      * HTTP Digest wrapper for PHP
      * 
      * @author YJSoft(yjsoft@yjsoft.pe.kr)
      * @version 1.0
      * @copyright YJSoft 2010-2016.
      * @license GNU Lesser General Public License, version 3
      */
    
    private $valid_id;
    
    /**
      * init from user id array
      *
      * @param array $login_id
      * @throws InvalidArgumentException if provided id is not array or no valid id is found.
      * @return bool
      */
    function __construct($login_id) {
        if(!is_array($login_id)) {
            throw new \InvalidArgumentException('Provided id was not array.');
        }
        
        foreach ($login_id as $id => $pw) {
            if(!$pw) {
                //if id has empty password, id will be ignored.
                unset($login_id[$id]);
                
                if(strpos($id,'"') !== FALSE || strpos($pw,'"') !== FALSE)
                {
                    //if id or pw has "(quote), id will be ignored.
                    unset($login_id[$id]);
                }
            }
        }
        
        if(!$login_id) {
            throw new \InvalidArgumentException('No valid id was found at array.');
        }
        
        $this->valid_id = $login_id;
    }
    
    /**
      * parse digest string
      *
      * parse digest string and return parsed data on success, false on failure.
      *
      * @param string $txt
      * @return array or bool
      */
    protected function http_digest_parse($txt) {
        $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
        $data = array();
        parse_str(str_replace(", ","&",$txt),$data);
        foreach ($data as $k => &$v)
        {
            $v = trim($v,"\"");
            unset($needed_parts[$k]);
        }
        return $needed_parts ? false : $data;
    }
    
    /**
      * check auth information
      *
      * get auth information fron PHP_AUTH_DIGEST and check if valid. if not valid, return false. else return true
      *
      * @param string $digest
      * @throws BadMethodCallException when called static
      * @return bool
      */
    public function is_auth($digest) {
        if(!isset($this)) {
            throw new \BadMethodCallException('This method cannot called static');
        }
        
        if(empty($digest)) {
            return false;
        }
        
        $data = $this->http_digest_parse($digest);
        
        //check missing data
        if($data === false) {
            return false;
        }
        
        //if 86400 second passed(1 day), auth will fail(prevent replay attack)
        if(abs(time() - base64_decode($data['nonce']))>86400) {
            return false;
        }
        
        $username = $data['username'];
        
        //check if id exists
        if(!isset($this->valid_id[$username])) {
            return false;
        }
        
        $ha1 = md5($username.':'.$data['realm'].':'.$this->valid_id[$username]);
        $ha2 = md5($_SERVER['REQUEST_METHOD'].':'.$data['uri']);
        $response = md5($ha1.':'.$data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'].':'.$ha2);
        
        //check if password match
        if($data['response'] != $response) {
            return false;
        }
        
        return true;
    }
    
    /**
      * send http 401 header to client
      *
      * @param string $realm
      *        string $nonce
      * @throws BadMethodCallException when called after header is sended
      * @return void
      */
    public static function sendAuthHeader($realm) {        
        if(headers_sent()) {
            throw new \BadMethodCallException('Cannot send auth header after header send');
        }
        
        $nonce = base64_encode(time());
        
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Digest realm="'.$realm.'",qop="auth",nonce="'.$nonce.'",opaque="'.md5($realm).'"');
    }
}