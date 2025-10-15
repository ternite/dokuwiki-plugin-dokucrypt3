<?php
/**
 * Plugin DokuCrypt2: Enables client side encryption
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Scott Moser <smoser@brickies.net>, Maintainer Sherri W. ( contact me at syntaxseed.com)
 */

if (!defined('DOKU_INC')) {
    die();
}
if (!defined('DOKU_PLUGIN')) {
    define('DOKU_PLUGIN', DOKU_INC.'lib/plugins/');
}
require_once(DOKU_PLUGIN.'action.php');

class action_plugin_dokucrypt2 extends DokuWiki_Action_Plugin
{
    public function register($controller)
    {
        $controller->register_hook('TPL_METAHEADER_OUTPUT', 'BEFORE', $this, 'c_hookjs');
        $controller->register_hook('DOKUWIKI_STARTED', 'AFTER', $this, '_addconfig');
    }

    public function c_hookjs(&$event, $param) {
        $event->data["script"][] = array(
            "type" => "text/javascript",
            "src" => DOKU_BASE."lib/plugins/dokucrypt2/init.js",
            "defer" => "defer",
            "_data" => ""
        );
    }
  
    public function _addconfig(&$event, $param)
    {
        global $JSINFO;
        $JSINFO['plugin_dokucrypt2_CONFIG_copytoclipboard'] = $this->getConf('copytoclipboard');
        $JSINFO['plugin_dokucrypt2_CONFIG_hidepasswordoncopytoclipboard'] = $this->getConf('hidepasswordoncopytoclipboard');
        $JSINFO['plugin_dokucrypt2_TEXT_copied_to_clipboard'] = $this->getLang('copied_to_clipboard');
	}
}
