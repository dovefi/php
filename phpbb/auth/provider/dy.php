<?php
/**
*
* This file is part of the phpBB Forum Software package.
*
* @copyright (c) phpBB Limited <https://www.phpbb.com>
* @license GNU General Public License, version 2 (GPL-2.0)
*
* For full copyright and license information, please see
* the docs/CREDITS.txt file.
*
*/

namespace phpbb\auth\provider;

/**
 * Database authentication provider for phpBB3
 * This is for authentication via the integrated user table
 */
class dy extends \phpbb\auth\provider\base
{
    protected $url_base;
    protected $sso_login;
    protected $sso_info;
    /**
    * phpBB passwords manager
    *
    * @var \phpbb\passwords\manager
    */
    protected $passwords_manager;
    /**
     * LDAP Authentication Constructor
     *
     * @param	\phpbb\db\driver\driver_interface		$db		Database object
     * @param	\phpbb\config\config		$config		Config object
     * @param	\phpbb\passwords\manager	$passwords_manager		Passwords manager object
     * @param	\phpbb\user			$user		User object
     */
    public function __construct(\phpbb\db\driver\driver_interface $db, \phpbb\config\config $config,
     \phpbb\passwords\manager $passwords_manager, \phpbb\user $user, \phpbb\request\request $request,
     $phpbb_root_path, $php_ext)
    {
        $this->db = $db;
        $this->config = $config;
        $this->passwords_manager = $passwords_manager;
        $this->user = $user;
        $this->request=$request;
        $this->phpbb_root_path = $phpbb_root_path;
        $this->php_ext = $php_ext;
        $this->url_base="http://bbs.dev.gdy.io/bbs";
        $this->sso_login="http://sso.dev.gdy.io/sso";
        $this->sso_info="http://127.0.0.1:1841/sso/api/uinfo";
        $this->sso_logout="http://127.0.0.1:1841/sso/api/logout";
    }
    
    public function get_uinfo($token)
    {
        $res=nil;
        $err=nil;
        for ($i=0;$i<3;$i++) {
            try {
                $data=file_get_contents($this->sso_info."?token=".$token);
                $res=json_decode($data);
                $err=nil;
                break;
            } catch (Exception $e) {
                $err=$e->getMessage();
            }
        }
        if ($err!=nil) {
            return array(
                    'code'             => -1,
                    'error_msg'        => $err,
                );
        }
        if (!isset($res->code)) {
            return array(
                    'code'             => -1,
                    'error_msg'        => "not code",
                );
        }
        if ($res->code!=0) {
            error_log("x1".$res->code);
            return array(
                    'code'          => $res->code,
                    'error_msg'     => "not code",
                );
        }
        if (!(isset($res->data)&&isset($res->data->usr)&&isset($res->data->usr->usr))) {
            return array(
                    'code'             => -1,
                    'error_msg'        => "not user",
                );
        }
        return array(
                    'code'       => 0,
                    'usr'        => $res->data->usr->usr[0],
                );
    }

    public function do_login($username)
    {
        $sql ='SELECT user_id, username, user_password, user_passchg, user_email, user_type
            FROM ' . USERS_TABLE . "
            WHERE username_clean = '" . $this->db->sql_escape(utf8_clean_string($username)) . "'";
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);

        if ($row) {
            // User inactive...
            if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE) {
                return array(
                    'status'        => LOGIN_ERROR_EXTERNAL_AUTH,
                    'error_msg'        => 'ACTIVE_ERROR',
                    'user_row'        => $row,
                );
            }
            // Successful login... set user_login_attempts to zero...
            return array(
                'status'        => LOGIN_SUCCESS,
                'error_msg'        => false,
                'user_row'        => $row,
            );
        } else {
            // retrieve default group id
            $sql = 'SELECT group_id
                FROM ' . GROUPS_TABLE . "
                WHERE group_name = '" . $this->db->sql_escape('REGISTERED') . "'
                    AND group_type = " . GROUP_SPECIAL;
            $result = $this->db->sql_query($sql);
            $row = $this->db->sql_fetchrow($result);
            $this->db->sql_freeresult($result);

            if (!$row) {
                trigger_error('NO_GROUP');
            }

            // generate user account data
            $ldap_user_row = array(
                'username'        => $username,
                'user_email'    => $username."@unset.com",
                'group_id'        => (int) $row['group_id'],
                'user_type'        => USER_NORMAL,
                'user_ip'        => $this->user->ip,
                'user_new'        => ($this->config['new_member_post_limit']) ? 1 : 0,
            );
            // this is the user's first login so create an empty profile
            return array(
                'status'        => LOGIN_SUCCESS_CREATE_PROFILE,
                'error_msg'        => false,
                'user_row'        => $ldap_user_row,
            );
        }
    }
    /**
     * {@inheritdoc}
     */
    public function login($username, $password)
    {
        if (!empty($this->user->data["is_registered"])) {
            return array(
                'status'        => LOGIN_SUCCESS,
                'error_msg'     => false,
                'user_row'      => array(
                    "user_id"   =>$this->user->data["user_id"],
                ),
            );
        }
        $token=$this->request->variable("token", "");
        if (empty($token)) {
            header("Location:".$this->sso_login."?url=".urlencode($this->url_base."/ucp.php?mode=login&login=external"));
            return;
        }
        $res=$this->get_uinfo($token);
        if ($res['code']==301) {
            header("Location:".$this->sso_login."?url=".urlencode($this->url_base."/ucp.php?mode=login&login=external"));
        } elseif ($res['code']!=0) {
            return array(
                    'status'        => LOGIN_ERROR_EXTERNAL_AUTH,
                    'error_msg'     => $res->error_msg,
            );
        }
        setcookie("token", $token, 1000*60*60*24*365);
        return $this->do_login($res['usr']);
    }

    /**
     * This function generates an array which can be passed to the user_add
     * function in order to create a user
     *
     * @param 	string	$username 	The username of the new user.
     * @param 	string	$password 	The password of the new user.
     * @return 	array 				Contains data that can be passed directly to
     *								the user_add function.
     */
    private function user_row($username, $password)
    {
        // first retrieve default group id
        $sql = 'SELECT group_id
			FROM ' . GROUPS_TABLE . "
			WHERE group_name = '" . $this->db->sql_escape('REGISTERED') . "'
				AND group_type = " . GROUP_SPECIAL;
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);

        if (!$row) {
            trigger_error('NO_GROUP');
        }

        // generate user account data
        return array(
            'username'        => $username,
            'user_email'    => $username."@unset.com",
            'group_id'        => (int) $row['group_id'],
            'user_type'        => USER_NORMAL,
            'user_ip'        => $this->user->ip,
            'user_new'        => ($this->config['new_member_post_limit']) ? 1 : 0,
        );
    }
    /**
    * {@inheritdoc}
    */
    public function autologin()
    {
        if (!empty($this->user->data["is_registered"])) {
            return array();
        }
        $token=$this->request->variable("token", "", false, 3);
        if (empty($token)) {
            return array();
        }
        $res=$this->get_uinfo($token);
        if ($res['code']!=0) {
            return array();
        }
        $username=$res['usr'];
        $sql = 'SELECT *
				FROM ' . USERS_TABLE . "
				WHERE username = '" . $this->db->sql_escape($username) . "'";
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);

        if ($row) {
            return ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE) ? array() : $row;
        }

        if (!function_exists('user_add')) {
            include($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
        }

            // create the user if he does not exist yet
        user_add($this->user_row($username, ""));

        $sql = 'SELECT *
				FROM ' . USERS_TABLE . "
				WHERE username_clean = '" . $this->db->sql_escape(utf8_clean_string($php_auth_user)) . "'";
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);
        if ($row) {
            return $row;
        }
        return array();
    }

        /**
    * {@inheritdoc}
    */
    public function logout($data, $new_session)
    {
        $token=$this->request->variable("token", "", false, 3);
        if (empty($token)) {
            return;
        }
        for ($i=0;$i<3;$i++) {
            try {
                file_get_contents($this->sso_logout."?token=".$token);
                break;
            } catch (Exception $e) {
            }
        }
        return;
    }
    /**
    * {@inheritdoc}
    */
    public function validate_session($user)
    {
        $token=$this->request->variable("token", "", false, 3);
        if (empty($token)) {
            return true;
        }
        $res=$this->get_uinfo($token);
        if ($res["code"]==0) {
            return $res['usr']==$user['username'];
        } else {
            return $user['user_type'] == USER_IGNORE;
        }
    }
}