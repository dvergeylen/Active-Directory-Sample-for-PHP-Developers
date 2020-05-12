<?php
    if(!isset($_SESSION)) {
        session_start();
    }
    include_once("conf/adfsconf.php");
	
	function redirectToAdfsSignInUrl($adfsConf, $context) {        
        header('Location: '. getAdfsSignInUrl($adfsConf, $context));
    }
    
    function redirectToAdfsSignOutUrl($adfsConf, $context) {        
        header('Location: '. getAdfsSignOutUrl($adfsConf, $context));
    }
    
    function getAdfsSignInUrl($adfsConf, $context) {
        return
            $adfsConf->adfsUrl.
            '?wa=wsignin1.0'.
            '&wct='.gmdate('Y-m-d\TH:i:s\Z', time()).
            '&wtrealm='. $adfsConf->spIdentifier.
            '&wctx='. $context;
    }
    
    function getAdfsSignOutUrl($adfsConf, $context) {
        return
            $adfsConf->adfsUrl.
            '?wa=wsignout1.0'.
            '&wct='.gmdate('Y-m-d\TH:i:s\Z', time()).
            '&wtrealm='. $adfsConf->spIdentifier.
            '&wctx='. $context;
    }
?>


<?php if($_REQUEST['authaction'] == 'Login') : ?>
	<?php 
		// Redirect to ADFS for Sign In.
		redirectToAdfsSignInUrl(AdfsConf::getInstance(), 'index.php');
	?>
<?php endif; ?>
<?php if($_REQUEST['authaction'] == 'Logout') : ?>
	<?php
		// Clear session and redirect to home page.
		unset($_SESSION['AdfsUserDetails']);
		header('Location: index.php');
		// N.B: could also be as below, but ADFS doesn't callback
		// This could be acceptable with a redirect link on the ADFS page (customizing the login page)
		// redirectToAdfsSignOutUrl(AdfsConf::getInstance(), 'index.php');
	?>
<?php endif; ?>