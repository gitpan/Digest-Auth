package Digest::Auth;

# ---  Required Packages
#use Carp;	  # Generate better errors with more context
use DBI;	  # Database connector
use CGI;	  # For the cookie handeling and output tools.
use strict;	  # Enforce restictions on good programming

# --- Headers --- 
my $PACKAGE = 'Auth';
my $VERSION = '0.01_2';
use vars qw($VERSION);

# Routines
sub new {
	my $package = shift;
	my %opts = @_;
	my $class = ref($package) || $package;

	my(%DM) = ( 
   	session => {	
		table		=> "session",
	        ip		=> "ip",
	        cert		=> "cert",
	        hash		=> "hash",
	        userid		=> "userid",
	        firstactive	=> "firstactive",
	        lastactive	=> "lastactive",
    	},
	sessionlocks => {
    		table		=> "sessionlocks",
	        ip		=> "ip",
	        stamp		=> "stamp",
	        cert		=> "cert",
	        hash		=> "hash",
	        userid		=> "userid",
        },	
	sessionattempts => {
 		table		=> "sessionattempts",
	        ip		=> "ip",
	        stamp		=> "stamp",
	        cert		=> "cert",
	        hash		=> "hash",
	        userid		=> "userid",
	        password	=> "password",
	},
	user => {		
                table		=> "user",
                userid		=> "userid",
                password	=> "password",
	},
	);

	# Options hash init
	my($self) = {
		dbh	=> undef,				# data base handel
		debug	=> 0,					# level of debug: 0=off,1=Error,2=Warn,3=Verbose 
		debuginfo  => "", 				# store debug information here.
		cookiename => "SessionCert",			# Cookie name to use for authorization
		domain     => ".",				# Domain name for cookie
		usecookies => 1,				# Use cookies to maintain sessions.
		digest   => "Digest::SHA1",			# Hash Digest to use
		connection => 86400,				# Maximum length of a authorized session. Default 24 hours
		validation => 600,				# Maximum amout of time for validation process. Default 10 minutes
		idletime   => 3600,				# Amount of time you can be inactive before being logged out. Default 60 minutes 
		initcertretry	=> 5,				# number of times to retry intitializing a session if the key is a duplicate
		forgiverate	=> 86400,			# Forgive bad login attempts after this much time or good login
		maxconperip	=> 10,				# Max connections/sessions per ip address
		maxconperuser	=> 1,				# Max connections/sessions per user name
		maxbadpass	=> 5,				# Max number of times a user can enter a bad password
		compatmode	=> 0,				# WARNING: THIS REDUCES SECURITY: Change to 1 to enable compatibility for non-javascript browsers. 
		locklength	=> [300,900,3600,86400,-1],	# Amount of time a user is locked/banned for a rule violation
		datamapping	=> \%DM,			# Data Mapping to modify the fieldnames for the database.
	};
	bless($self, $class);
	$self->DebugAdd($PACKAGE."->new()::Initialized",3);
	my($bitbucket) = $self->Put(%opts);
	return $self;
}

sub Get{
	my($self,$opt1,$opt2,$opt3) = @_;
	my $result;
	$self->DebugAdd($PACKAGE."->Get($opt1,$opt2,$opt3)::Initialized",3);
	
	$opt1 =~ s/[^\w]//g;
	$opt1 = lc($opt1);

	$opt2 =~ s/[^\w]//g;
	$opt2 = lc($opt2);
	
	$opt3 =~ s/[^\w]//g;
	$opt3 = lc($opt3);	
	
	if(exists $self->{$opt1}){
		if($opt1 eq "datamapping"){
			if(exists $self->{datamapping}{$opt2}){
				if(exists $self->{$opt1}{$opt2}{$opt3}){
					return $self->{$opt1}{$opt2}{$opt3};
				}else{
					return $result; # no result
				}
			}else{
				return $result; # no result
			}
		}else{
			return $self->{$opt1}; 
		}
	}else{
		return $result; # no result
	}
}
sub Put{
	my($self,%opt) = @_;
	my($result)= 0;
	$self->DebugAdd($PACKAGE."->Put()::Initialized",3);

	if(exists $opt{dbh}){
		$result++; $self->{dbh} = $opt{dbh};
	}
	if(exists $opt{debug} && $self->SanitizeData($opt{debug}) && $opt{debug} >= 0 && $opt{debug} <= 3){
		$result++; $self->{debug} = $opt{debug};
	}
	if(exists $opt{digest}){
		$result++; $self->{digest} = $opt{digest};
	}	
	if(exists $opt{cookiename} && $self->SanitizeData($opt{cookiename},1)){
		$result++; $self->{cookiename} = $opt{cookiename};
	}
	if(exists $opt{domain} && $self->SanitizeData($opt{domain},4)){
		$result++; $self->{domain} = $opt{domain};
	}
	if(exists $opt{usecookies} && ($opt{usecookies} == 0 || $opt{usecookies} == 1)){
		$result++; $self->{usecookies} = $opt{usecookies};
	}	
	if(exists $opt{connection} && $self->SanitizeData($opt{connection},3)){
		$result++; $self->{connection} = $opt{connection};
	}
	if(exists $opt{validation} && $self->SanitizeData($opt{validation},3)){
		$result++; $self->{validation} = $opt{validation};
	}
	if(exists $opt{idletime} && $self->SanitizeData($opt{idletime},3)){ 
		$result++; $self->{idletime} = $opt{idletime}; 
	}
	if(exists $opt{initcertretry} && $self->SanitizeData($opt{initcertretry})){ 
		$result++; $self->{initcertretry} = $opt{initcertretry}; 
	}
	if(exists $opt{forgiverate} && $self->SanitizeData($opt{forgiverate})){ 
		$result++; $self->{forgiverate} = $opt{forgiverate}; 
	}
	if(exists $opt{maxconperip} && $self->SanitizeData($opt{maxconperip},3)){ 
		$result++; $self->{maxconperip} = $opt{maxconperip}; 
	}
	if(exists $opt{maxconperuser} && $self->SanitizeData($opt{maxconperuser},3)){ 
		$result++; $self->{maxconperuser} = $opt{maxconperuser}; 
	}
	if(exists $opt{maxbadpass} && $self->SanitizeData($opt{maxbadpass},3)){ 
		$result++; $self->{maxbadpass} = $opt{maxbadpass}; 
	}
	if(exists $opt{compatmode} && $self->SanitizeData($opt{compatmode}) && ($opt{compatmode} == 1 || $opt{compatmode} == 0)){ 
		$result++; $self->{compatmode} = $opt{compatmode}; 
	}
	if(exists $opt{locklength} && $self->SanitizeData($opt{locklength},3)){ 
		$result++; $self->{locklength} = $opt{locklength}; 
	}
	if(exists $opt{datamapping}{session}{table} && $self->SanitizeData($opt{datamapping}{session}{table},2)){ 
		$result++; $self->{datamapping}{session}{table} = $opt{datamapping}{session}{table}; 
	}
	if(exists $opt{datamapping}{session}{ip} && $self->SanitizeData($opt{datamapping}{session}{ip},2)){ 
		$result++; $self->{datamapping}{session}{ip} = $opt{datamapping}{session}{ip}; 
	}
	if(exists $opt{datamapping}{session}{cert} && $self->SanitizeData($opt{datamapping}{session}{cert},2)){ 
		$result++; $self->{datamapping}{session}{cert} = $self->{datamapping}{session}{cert};  
	}
	if(exists $opt{datamapping}{session}{hash} && $self->SanitizeData($opt{datamapping}{session}{hash},2)){ 
		$result++; $self->{datamapping}{session}{hash} = $opt{datamapping}{session}{hash};  
	}
	if(exists $opt{datamapping}{session}{userid} && $self->SanitizeData($opt{datamapping}{session}{userid},2)){ 
		$result++; $self->{datamapping}{session}{userid} = $opt{datamapping}{session}{userid}; 
	}
	if(exists $opt{datamapping}{session}{firstactive} && $self->SanitizeData($opt{datamapping}{session}{firstactive},2)){ 
		$result++; $self->{datamapping}{session}{firstactive} = $opt{datamapping}{session}{firstactive}; 
	}
	if(exists $opt{datamapping}{session}{lastactive} && $self->SanitizeData($opt{datamapping}{session}{lastactive},2)){ 
		$result++; $self->{datamapping}{session}{lastactive} = $opt{datamapping}{session}{lastactive}; 
	}
	if(exists $opt{datamapping}{sessionlocks}{table} && $self->SanitizeData($opt{datamapping}{sessionlocks}{table},2)){ 
		$result++; $self->{datamapping}{sessionlocks}{table} = $opt{datamapping}{sessionlocks}{table}; 
	}
	if(exists $opt{datamapping}{sessionlocks}{ip} && $self->SanitizeData($opt{datamapping}{sessionlocks}{ip},2)){ 
		$result++; $self->{datamapping}{sessionlocks}{ip} = $opt{datamapping}{sessionlocks}{ip}; 
	}
	if(exists $opt{datamapping}{sessionlocks}{stamp} && $self->SanitizeData($opt{datamapping}{sessionlocks}{stamp},2)){ 
		$result++; $self->{datamapping}{sessionlocks}{stamp} = $opt{datamapping}{sessionlocks}{stamp};  
	}
	if(exists $opt{datamapping}{sessionlocks}{cert} && $self->SanitizeData($opt{datamapping}{sessionlocks}{cert},2)){ 
		$result++; $self->{datamapping}{sessionlocks}{cert} = $opt{datamapping}{sessionlocks}{cert};  
	}
	if(exists $opt{datamapping}{sessionlocks}{hash} && $self->SanitizeData($opt{datamapping}{sessionlocks}{hash},2)){ 
		$result++; $self->{datamapping}{sessionlocks}{hash} = $opt{datamapping}{sessionlocks}{hash};  
	}
	if(exists $opt{datamapping}{sessionlocks}{userid} && $self->SanitizeData($opt{datamapping}{sessionlocks}{userid},2)){ 
		$result++; $self->{datamapping}{sessionlocks}{userid} = $opt{datamapping}{sessionlocks}{userid};  
	}
	if(exists $opt{datamapping}{sessionattempts}{table} && $self->SanitizeData($opt{datamapping}{sessionattempts}{table},2)){ 
		$result++; $self->{datamapping}{sessionattempts}{table} = $opt{datamapping}{sessionattempts}{table}; 
	}
	if(exists $opt{datamapping}{sessionattempts}{ip} && $self->SanitizeData($opt{datamapping}{sessionattempts}{ip},2)){ 
		$result++; $self->{datamapping}{sessionattempts}{ip} = $self->{datamapping}{sessionattempts}{ip}; 
	}
	if(exists $opt{datamapping}{sessionattempts}{stamp} && $self->SanitizeData($opt{datamapping}{sessionattempts}{stamp},2)){ 
		$result++; $self->{datamapping}{sessionattempts}{stamp} = $opt{datamapping}{sessionattempts}{stamp};  
	}
	if(exists $opt{datamapping}{sessionattempts}{cert} && $self->SanitizeData($opt{datamapping}{sessionattempts}{cert},2)){ 
		$result++; $self->{datamapping}{sessionattempts}{cert} = $opt{datamapping}{sessionattempts}{cert};  
	}
	if(exists $opt{datamapping}{sessionattempts}{hash} && $self->SanitizeData($opt{datamapping}{sessionattempts}{hash},2)){ 
		$result++; $self->{datamapping}{sessionattempts}{hash} = $opt{datamapping}{sessionattempts}{hash};  
	}
	if(exists $opt{datamapping}{sessionattempts}{userid} && $self->SanitizeData($opt{datamapping}{sessionattempts}{userid},2)){
		$result++; $self->{datamapping}{sessionattempts}{userid} = $opt{datamapping}{sessionattempts}{userid};  
	}
	if(exists $opt{datamapping}{sessionattempts}{password} && $self->SanitizeData($opt{datamapping}{sessionattempts}{password},2)){ 
		$result++; $self->{datamapping}{sessionattempts}{password} = $opt{datamapping}{sessionattempts}{password};  
	}
	if(exists $opt{datamapping}{user}{table} && $self->SanitizeData($opt{datamapping}{user}{table},2)){ 
		$result++; $self->{datamapping}{user}{table} = $opt{datamapping}{user}{table}; 
	}
	if(exists $opt{datamapping}{user}{userid} && $self->SanitizeData($opt{datamapping}{user}{userid},2)){ 
		$result++; $self->{datamapping}{user}{userid} = $opt{datamapping}{user}{userid}; 
	}
	if(exists $opt{datamapping}{user}{password} && $self->SanitizeData($opt{datamapping}{user}{password},2)){ 
		$result++; $self->{datamapping}{user}{password} = $opt{datamapping}{user}{password}; 
	}

	return $result;
}
sub Keygen {
	# Creates a somewhat random key of $QueKeyLength size using numbers 
	# and uppercase and lowercase letters based on $complexity.
	my($self,
	   $QueKeyLength,
	   $complexity)=@_; 
	my(@keys);
	my($key) = "";
	$self->DebugAdd($PACKAGE."->Keygen()::Initialized",3);
	
	if($QueKeyLength < 1 || $QueKeyLength > 128 ){ $QueKeyLength = 10; }
	if($complexity == 1){	  
		@keys = ('A'..'Z');
	}elsif($complexity == 2){ 
		@keys = ('A'..'Z','0'..'9');
	}else{ 		          
		@keys = ('A'..'Z','a'..'z','0'..'9'); 
	}
	for(my($a)=1; $a <= $QueKeyLength; $a++){ $key .= $keys[ int( rand($#keys)) ]; }
	return $key;
}
sub SanitizeData{
	# do a test to see if there are any special characters
	my($self,$data1,$opt) = @_;
	my($result)=0;
	my($data2) = $data1;
	if($opt == 1){ # letters and numbers with underscore "_"
		$data2 =~ s/[^a-zA-Z0-9_]//g;
	}elsif($opt == 2){ # only letters and numbers
		$data2 =~ s/[^a-zA-Z0-9]//g;
	}elsif($opt == 3){ # positive or neg numbers 
		$data2 =~ s/[^0-9\-]//g;
	}elsif($opt == 4){ # lower case letters numbers and dots + dashes
		$data2 =~ s/[^a-z0-9\.\-]//g;
	}else{ # positive numbers only 
		$data2 =~ s/[^0-9]//g;
	}
	if($data1 eq $data2){
		$result++;}	
	return $result
}
sub AutoAuth{
	# Automatically Authorize the user.
	my($self,%opts) = @_;
	my($result)=0;
	$self->DebugAdd($PACKAGE."->AutoAuth()::Initialized",3);
	
	if( defined($self->{user}) && defined($self->{hash})){
		$result = "Authorize";
		# $self->Authorize(%opts);
	
	}elsif( defined($opts{cert}) ){
		$result = "Validate";
		# $self->Validate(%opts);
	
	}else{
		$result = "Initialize";
		# $self->Initialize(%opts);
		
	}
	
	return $result;
}
sub UserAdd{
	# insert data into user table for login credentials
	my($self, %opts) = @_;
	my($redflag) = 0;
	my($result) = 0;
	my($hits) = 0;
	$self->DebugAdd($PACKAGE."->UserAdd()::Initialized",3);
	
	if(! $self->SanitizeData($opts{user},1)){$redflag++;}
	
	# Check for user in the system
	# We have two methods to sanitize databases with.
	# We are using DBI::quote since we want to keep this extensible.
	# on the front end after the DBH is created if it is a SQL database it will be the 
	# programmers responisbility to first parse it with method no. 1. We will try to 
	# keep things neat using method no. 2.
	# 1. mysql_real_escape_string();
	# 2. $self->{dbh}->quote();
	my($sql)='SELECT COUNT(*) AS HITS FROM ' 
		. $self->{datamapping}{user}{table}
		. ' WHERE '
		. $self->{datamapping}{user}{userid} 
		. ' = '
		. $self->{dbh}->quote( $opts{user} );

	my($sth) = $self->{dbh}->prepare($sql);
	$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->UserAdd()::Check",$sql, $!),1);
	while (my $ref = $sth->fetchrow_hashref()){
		$hits = $ref->{'HITS'};
	}
	$sth->finish();		

	# if user is not in the system, add them, otherwise fail gracefully
	if($hits == 0){
		# create user, they are not in the system
		my($sql)='INSERT INTO ' 
			. $self->{datamapping}{user}{table}
			. ' ('
			. $self->{datamapping}{user}{userid}
			. ', '
			. $self->{datamapping}{user}{password}
			. ') VALUES ('
			. ' '
			. $self->{dbh}->quote($opts{user})
			. ', '
			. $self->{dbh}->quote($opts{password})
			. ')';
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->UserAdd()::Add",$sql, $!),1);
		$sth->finish();	
		$result=2;
	}else{
		# user in the system already
		$self->DebugAdd($PACKAGE."->UserAdd()::User Exists{".$opts{user}."}",2);
		$result=1;
	}
	return $result;
}

sub Initialize{
	my($self) = @_;
	my($result) = 0;
	my($cert);
	my($ip) = $ENV{'REMOTE_ADDR'};
	my($stamp) = time();
	
	$self->DebugAdd($PACKAGE."->Initialize()::Initialized",3);
		# insert data into sessions table to establish a login session

	my($login) = 0;	# toggles to 1 when successfull
	my($max)   = 0;	# max number of trys for system safety when testing
	my($hits)  = 0;
		
	while ($login <= 0 && $max < $self->{initcertretry}){ # make sure it is a unique entry
				
		$cert = $self->Keygen(10,2);
			
		my($sql)="SELECT COUNT(*) AS HITS FROM "
			. $self->{datamapping}{session}{table}
			. " WHERE "
			. $self->{datamapping}{session}{ip}
			. " = "
			. $self->{dbh}->quote($ip)
			. " AND "
			. $self->{datamapping}{session}{cert}
			. " = "
			. $self->{dbh}->quote($cert);
			
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Initialize()",$sql, $!),1);
		while (my $ref = $sth->fetchrow_hashref()){
			$hits = $ref->{'HITS'};
		}
		$sth->finish();
		if($hits == 0){
			$login++;
		}else{
			$max++;
			$self->DebugAdd($self->SQL_Die("Initialize()::CreateCert::CertCollision",$sql,"Debug"),2);
		}
	}
	if($hits ==  0){
		# initialize the session transaction.
		my($sql) = "INSERT INTO "
			. $self->{datamapping}{session}{table}
			. " ("
			. $self->{datamapping}{session}{cert}
			. ","
			. $self->{datamapping}{session}{ip}
			. ","
			. $self->{datamapping}{session}{firstactive}
			. ","
			. $self->{datamapping}{session}{lastactive}
			. ") VALUES("
			. $self->{dbh}->quote($cert)
			. ","
			. $self->{dbh}->quote($ip)
			. ","
			. $self->{dbh}->quote($stamp)
			. ","
			. $self->{dbh}->quote($stamp)
			. ")";
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Initialize()",$sql, $!),1);
		$sth->finish();
		$result++;
	}	
	# temp measure cert, ip, stamp should not be global var's
	# $self->{cert} = $cert;
	# $self->{ip} = $ip
	# $self->{stamp} = $stamp
	return (cert => $cert, 
	        ip => $ip, 
	        stamp => $stamp);
}

sub Validate{
	# ops{userid, cert, hash, pass}
	# userid, cert, (hash || password) required
	# 	+ use only hash when self->compatmode = 0
	#  	+ use only pass when self->compatmode = 1 

	my($self,%opts) = @_; 
	$self->DebugAdd($PACKAGE."->Validate()::Initialized",3);
	
	my($hash);
	my($cert);
	my($ip)     = $ENV{'REMOTE_ADDR'};
	my($stamp)  = time();		
	my($result) = 0;
	my($hits)   = 0;
	my($cookiedata)="";

	# TODO: Need to build validation for this

	# Find all matching record for the primary key (Key,IP Address)
	my(%SQL_SESSION);
	my($sql) = "SELECT * FROM " 
		. $self->{datamapping}{session}{table}
		. " WHERE "
		. $self->{datamapping}{session}{cert}
		. " = "
		. $self->{dbh}->quote($opts{cert})
		. " AND " 
		. $self->{datamapping}{session}{ip}
		. " = "
		. $self->{dbh}->quote($ip)
		. " LIMIT 0,1";
	my($sth) = $self->{dbh}->prepare($sql);
	$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Validate()",$sql, $!),1);
	while (my $ref = $sth->fetchrow_hashref()){
		$SQL_SESSION{firstactive} = $ref->{$self->{datamapping}{session}{firstactive}};
	}
	$sth->finish();
	
	if( ! $SQL_SESSION{firstactive} ){
		# no: stop / log attempt; (Key,IP Address) not found in sessions. Log to sessionattempts
		# ops{user, cert, hash, pass}
		$self->DebugAdd($PACKAGE."->Validate()::Active(Key,IP Address) Not Found",2);
		my($sql) = "INSERT INTO "
			. $self->{datamapping}{sessionattempt}{table}
			. " ("
			. $self->{datamapping}{sessionattempt}{cert}
			. ","
			. $self->{datamapping}{sessionattempt}{ip}
			. ","
			. $self->{datamapping}{sessionattempt}{stamp}
			. ","
			. $self->{datamapping}{sessionattempt}{userid}
			. ","
			. $self->{datamapping}{sessionattempt}{hash}
			. ","
			. $self->{datamapping}{sessionattempt}{password}
			. ") VALUES("
			. $self->{dbh}->quote($opts{cert})
			. ","
			. $self->{dbh}->quote($ip)
			. ","
			. $self->{dbh}->quote($stamp)
			. ","
			. $self->{dbh}->quote($opts{userid})
			. ","
			. $self->{dbh}->quote($opts{hash})
			. ","
			. $self->{dbh}->quote($opts{password})
			. ")";
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Initialize()",$sql, $!),1);
		$sth->finish();
	}else{
		# Yes: continue
		# Get the specified Username given from the client from the user table
		my(%SQL_USER);
		my($sql) = "SELECT * FROM "
			. $self->{datamapping}{user}{table}
			. " WHERE "
			. $self->{datamapping}{user}{userid}
			. " = "
			. $self->{dbh}->quote($opts{userid});
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Validate()",$sql, $!),1);
		while (my $ref = $sth->fetchrow_hashref()){
			$SQL_USER{password} = $ref->{$self->{datamapping}{user}{password}};
			$SQL_USER{userid}   = $ref->{$self->{datamapping}{user}{userid}};
		}
		$sth->finish();
				
		# if(Is username Found?){Yes: continue}else{no: stop}
		# -----TODO		

		# Create a secure 1 way Hash of the Username, Key, and Password
		
		my($digestdata) = ($opts{userid} . $opts{cert} . $SQL_USER{password} . $SQL_SESSION{firstactive} );
		
		$hash = $self->DigestMake(data => $digestdata);

		# if compat mode, ignore hash arg and build the hash without javascript
		if($self->{compatmode} != 0){
			$self->DebugAdd($PACKAGE."->Validate()::CompatMode=1",3);
			my($digestdata2) = ($opts{userid} . $opts{cert} . $opts{password} . $SQL_SESSION{firstactive});
			$opts{hash} = $self->DigestMake(data => $digestdata);
		}

		

		# Test the hashes against eachother on a time sensitive manner
		if( $hash eq $opts{hash} && 
		    $stamp <= ($SQL_SESSION{firstactive} + $self->{validation})
		  ){

			# -----TODO
			# this deletes anything, but we have to make it match our prefrences for the max number of user logins
			# we do need some sort of cleanup though here.. this SQL statement needs revision
			#	my($sql) = "DELETE * FROM " 
			#		. $self->{datamapping}{session}{table}
			#		. " WHERE NOT "
			#		. $self->{datamapping}{session}{userid}
			#		. " = "
			#		. $self->{dbh}->quote($opts{userid})
			#		. " AND "
			#		. $self->{datamapping}{session}{cert}
			#		. " = "
			#		. $self->{dbh}->quote($opts{cert})
			#		. " AND "
			#		. $self->{datamapping}{session}{ip}
			#		. " = "
			#		. $self->{dbh}->quote($ip);
			#	print $self->SQL_Die("Validate()",$sql,"Debug");
			#	# $self->DebugAdd( $self->SQL_Die("Validate()",$sql,"Debug") );
			#	my($sth) = $self->{dbh}->prepare($sql);
			#	$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Validate()",$sql, $!),1);
			#	$sth->finish();
				
				my($sql) = "UPDATE "
					. $self->{datamapping}{session}{table}
					. " SET "
					. $self->{datamapping}{session}{lastactive}
					. " = "
					. $self->{dbh}->quote($stamp)
					. ", "
					. $self->{datamapping}{session}{hash}
					. " = "
					. $self->{dbh}->quote($hash)
					. ", "
					. $self->{datamapping}{session}{userid}
					. " = "
					. $self->{dbh}->quote($opts{userid})
					. " WHERE "
					. $self->{datamapping}{session}{cert}
					. " = "
					. $self->{dbh}->quote($opts{cert})
					. " AND "
					. $self->{datamapping}{session}{ip}
					. " = "
					. $self->{dbh}->quote($ip);
				# $self->DebugAdd( $self->SQL_Die("Validate()",$sql,"Debug") );
				my($sth) = $self->{dbh}->prepare($sql);
				$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Validate()",$sql, $!),1);
				$sth->finish();
				# TODO: actions:
				# delete all previous sessions for username (1 session per user)
			
				$result = 1;
			}else{ 
				# failed to validate
				# print "'$hash' is ne '".$opts{hash}."' <br />OR<br /> " .$stamp ." is not <= ". ($SQL_SESSION{firstactive} + $self->{validation})."<br />";
			}	
	}
	if($self->{usecookies}){
		$cookiedata = $self->CookieSet(data => "userid:".$opts{userid}.",hash:".$hash);
	}
	return (result => $result, 
	        userid => $opts{userid}, 
	        hash => $hash,
	        cookie => $cookiedata);
}

sub Authorize{
	my($self,%opts) = @_;
	# ops{userid, hash}

	my($ip) = $ENV{'REMOTE_ADDR'};
	my($stamp) = time();	
	my($result) = 0;
	my($hits) = 0;
	$self->DebugAdd($PACKAGE."->Authorize()::Initialized",3);

	# rules:
	# CERT{hash} eq SQL.session{hash}
	# CERT{userid} eq SQL.session{userid}
	# Parsed{ip} eq SQL.session{ip}
	#  ($SQL_SESSION{firstactive} + $connection) = $stamp &&
	#  ($SQL_SESSION{lastactive} + $idletime) >= $stamp
	# actions:
	# session{lastactive} = Parsed{time}

	my(%SQL_SESSION);
	my($sql)="SELECT * FROM " 
		. $self->{datamapping}{session}{table}
		. " WHERE "
		. $self->{datamapping}{session}{hash}
		. " = "
		. $self->{dbh}->quote($opts{hash})
		. " AND "
		. $self->{datamapping}{session}{userid}
		. " = "
		. $self->{dbh}->quote($opts{userid})
		. " AND "
		. $self->{datamapping}{session}{ip}
		. " = "
		. $self->{dbh}->quote($ip)
		. " LIMIT 0,1";
	my($sth) = $self->{dbh}->prepare($sql);
	$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Authorize()",$sql, $!),1);
	while (my $ref = $sth->fetchrow_hashref()){
		$SQL_SESSION{firstactive} = $ref->{ $self->{datamapping}{session}{firstactive} };
		$SQL_SESSION{lastactive} = $ref->{ $self->{datamapping}{session}{lastactive} };
	}
	$sth->finish();
	
	if( (($SQL_SESSION{firstactive} + $self->{connection}) >= $stamp) &&
	    (($SQL_SESSION{lastactive} + $self->{idletime}) >= $stamp)
	){
		# Is the user session active valid? if it is update session table;
		my($sql) = "UPDATE "
			. $self->{datamapping}{session}{table}
			. " SET "
			. $self->{datamapping}{session}{lastactive}
			. " = "
			. $self->{dbh}->quote($stamp)
			. " WHERE "
			. $self->{datamapping}{session}{hash}
			. " = "
			. $self->{dbh}->quote($opts{hash})
			. " AND "
			. $self->{datamapping}{session}{userid}
			. " = "
			. $self->{dbh}->quote($opts{userid})
			. " AND "
			. $self->{datamapping}{session}{ip}
			. " = "
			. $self->{dbh}->quote($ip);
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->Authorize()",$sql, $!),1);
		$sth->finish();
		$result++;
	}else{
		# Note the invalid attempt
	}
	return $result;
}

sub DigestMake{
	my($self,%opts) = @_;
	$self->DebugAdd($PACKAGE."->Authorize()::DigestMake",3);

	my($DIGEST); my($HASH);

	if($self->{digest} eq "Digest::SHA1"){
		use Digest::SHA1;
		$DIGEST = Digest::SHA1->new;
		$DIGEST->add( $opts{data} );
		$HASH = $DIGEST->hexdigest;
	}elsif($self->{digest} eq "MD5"){
		use Digest::MD5;
		$DIGEST = Digest::MD5->new;
		$DIGEST->add( $opts{data} );
		$HASH = $DIGEST->hexdigest;	
	}else{
		# Might do this way instead:
		##################################################
		# use Package::Alias DIGESTNAME => $self->digest;
		# use DIGESTNAME;
		# $DIGEST = DIGESTNAME->new;
		# $DIGEST->add($opts{data});
		# $HASH = $DIGEST->hexdigest;
		##################################################
		
		eval ('use '.$self->digest);
		eval ('$DIGEST = '.$self->digest.'->new');
		$DIGEST->add($opts{data});
		$HASH = $DIGEST->hexdigest;
	}
	return $HASH;
}

sub DeleteExpiredSessions {
	# scrubs any expired sessions
	my($self,%opts) = @_;
	my($result) = 0;
	
	return $result;
}

sub TableMake{
	my($self, %opts) = @_;
	my($result) = 0;
	$self->DebugAdd($PACKAGE."->TableMake()::Initialized",3);

	if(defined($opts{'table'}) && (lc($opts{'table'}) eq 'all'|| lc($opts{'table'}) eq 'session')){
		$self->DebugAdd($PACKAGE."->TableMake()::CreatingTable::Session",3);
		my($sql)= qq^CREATE TABLE IF NOT EXISTS ^ . $self->{datamapping}{session}{table}
			 . qq^ (^ . $self->{datamapping}{session}{ip}
			 . qq^ VARCHAR(15) NOT NULL, ^ . $self->{datamapping}{session}{cert}
			 . qq^ VARCHAR(10) NOT NULL, ^ . $self->{datamapping}{session}{hash}
			 . qq^ VARCHAR(45), ^ . $self->{datamapping}{session}{userid}
			 . qq^ VARCHAR(45), ^ . $self->{datamapping}{session}{firstactive}
			 . qq^ VARCHAR(45), ^ . $self->{datamapping}{session}{lastactive}
			 . qq^ VARCHAR(45), PRIMARY KEY(^ . $self->{datamapping}{session}{ip}
			 . qq^, ^ . $self->{datamapping}{session}{cert}
			 . qq^))^;
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->TableMake(table => '".$opts{'table'}."')::Create Table::Session::Execute",$sql, $!),1);
		$sth->finish();
		$result++;
	}

	if(defined($opts{'table'}) && (lc($opts{'table'}) eq 'all'|| lc($opts{'table'}) eq 'sessionattempts')){
		$self->DebugAdd($PACKAGE."->TableMake()::CreatingTable::SessionAttempts",3);
		my($sql)= qq^CREATE TABLE IF NOT EXISTS ^.$self->{datamapping}{sessionattempts}{table}
			 .qq^ (^.$self->{datamapping}{sessionattempts}{ip}
			 .qq^ varchar(15) NOT NULL, ^.$self->{datamapping}{sessionattempts}{stamp}
			 .qq^ varchar(10) NOT NULL, ^.$self->{datamapping}{sessionattempts}{hash}
			 .qq^ varchar(45) default NULL, ^.$self->{datamapping}{sessionattempts}{userid}
			 .qq^ varchar(45) default NULL, ^.$self->{datamapping}{sessionattempts}{cert}
			 .qq^ varchar(45) default NULL, ^.$self->{datamapping}{sessionattempts}{password}
			 .qq^ varchar(45) default NULL, PRIMARY KEY(^.$self->{datamapping}{sessionattempts}{ip}
			 .qq^, ^.$self->{datamapping}{sessionattempts}{stamp}
			 .qq^))^;
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->TableMake(table => '".$opts{'table'}."')::Create Table::SessionAttempts::Execute",$sql, $!),1);
		$sth->finish();
		$result++;
	}
	
	if(defined($opts{'table'}) && (lc($opts{'table'}) eq 'all'|| lc($opts{'table'}) eq 'sessionlocks')){
		$self->DebugAdd($PACKAGE."->TableMake()::CreatingTable::SessionLocks",3);
		my($sql)= qq^CREATE TABLE IF NOT EXISTS ^.$self->{datamapping}{sessionlocks}{table}
			 .qq^ (^.$self->{datamapping}{sessionlocks}{ip}
			 .qq^ varchar(15) NOT NULL, ^.$self->{datamapping}{sessionlocks}{stamp}
			 .qq^ varchar(10) NOT NULL, ^.$self->{datamapping}{sessionlocks}{hash}
			 .qq^ varchar(45) default NULL, ^.$self->{datamapping}{sessionlocks}{userid}
			 .qq^ varchar(45) default NULL, ^.$self->{datamapping}{sessionlocks}{cert}
			 .qq^ varchar(45) default NULL, PRIMARY KEY(^.$self->{datamapping}{sessionlocks}{ip}
			 .qq^,^.$self->{datamapping}{sessionlocks}{stamp}
			 .qq^))^;
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->TableMake(table => '".$opts{'table'}."')::Create Table::SessionLocks::Execute",$sql, $!),1);
		$sth->finish();
		$result++;
	}
	
	if(defined($opts{'table'}) && (lc($opts{'table'}) eq 'all'|| lc($opts{'table'}) eq 'user')){
		$self->DebugAdd($PACKAGE."->TableMake()::CreatingTable::User",3);
		my($sql)= qq^CREATE TABLE IF NOT EXISTS ^.$self->{datamapping}{user}{table}
			 .qq^ (^.$self->{datamapping}{user}{userid}
			 .qq^ varchar(50) NOT NULL,^.$self->{datamapping}{user}{password}
			 .qq^ varchar(50) default NULL, PRIMARY KEY(^.$self->{datamapping}{user}{userid}
			 .qq^))^;
		my($sth) = $self->{dbh}->prepare($sql);
		$sth->execute() or $self->DebugShow($self->SQL_Die("Auth->TableMake(table => '".$opts{'table'}."')::Create Table::User::Execute",$sql, $!),1);
		$sth->finish();
		$result++;
	}	
	return $result; # Number of SQL statements processed successfully. 
}

sub SQL_Die{
	# Deguging tool: Helps neatly print SQL statements out when module for debug messages.
	my($self, $subroutine, $sql, $err) = @_;
	my(@keys)=("FROM","WHERE","VALUES","SET","OR","AND","LIMIT","ORDER","BETWEEN","IN", "AS", "UNION", "INTO", "IF");
	my($cnt)= "\n<pre style=\"background-color: white; width: 500px; height: 100px; overflow:scroll; font-family: Courier, monospace; font-size: 8pt; border: 1px black solid;\">";
	for(my($a) = 0; $a <= $#keys; $a++){
		my($b) = " " . $keys[$a] . " "; 
		my($c) = "\n" . $b; 
		$sql =~ s/$b/$c/gi;
	}
	$sql =~ s/, /,\n  /g;
	return ("\n<div style=\"font-size: 12pt; width: 510px; background-color: #FFCCCC; border: 1px #990000 solid; padding: 4px; margin: 0px;\">\n<b>Can not execute SQL statement $PACKAGE->". $subroutine ."</b>". $cnt . $sql .";</pre>\n$err\n</div>");
}
sub DebugAdd{
	# Deguging tool: Appends debugging information to the main module.
	my($self,$data,$level) = @_;
	if($self->{debug} >= $level){
		my($leveltext)="";
		if($level == 1){
			$leveltext = "Error";
		}elsif($level == 2){
			$leveltext = "Warning";
		}elsif($level == 3){
			$leveltext = "Infomation";
		}else{
			$leveltext = "Unknown";
		}
		$self->{debuginfo} .= "<br /><b>".$leveltext."</b>: Time: " . localtime() . " [" . time() . "]<br />" . $data;
	}
}
sub DebugShow{
	my($self,$data,$level) = @_;
	$self->DebugAdd($data,$level);
	if($self->{debug} > 0){
		print $self->{debuginfo};
	}
}

sub CookieGet {
	# move cookies to a hash
	my($self,%opts) = @_;
	$self->DebugAdd($PACKAGE."->CookieGet()::Initialized",3);
	my(%result);
	my($nm)  = ( defined($opts{name}) )? $opts{name} : $self->{cookiename};
	my($query) = new CGI;
	my(@cookies) = split(/;/, $query->cookie($nm));
	
	for (my($a)=0; $a <= $#cookies; $a++){
		my @pairs = split(/,/,$cookies[$a]); 
		for (my($b)=0; $b <= $#pairs; $b++){
			my($n,$v) = split(/:/, $pairs[$b]) ; 
			$result{$n} = $v;
		}
		last;
	}
	return (%result);
}

sub CookieSet {
	# move data to a cookie
	my($self,%opts) = @_;
	$self->DebugAdd($PACKAGE."->CookieWrite()::Initialized",3);
	
	my($query) = new CGI;
	my($nm)    = ( defined($opts{name}) )? $opts{name} : $self->{cookiename};
	my($domain)= ( defined($opts{domain}) )? $opts{domain} : $self->{domain};
	my($path)  = ( defined($opts{path}) )? $opts{path} : "/";
	my($gmt)   = ( defined($opts{gmt}) )? $opts{gmt} : gmtime(time() + $self->{idletime})." GMT;";
	my($cookie)= $query->cookie(-domain  => $domain,
				    -name    => $nm,
	               		    -value   => $opts{data},
	               		    -expires => $gmt,
	               		    -path    => $path);
	
	print "Set-Cookie: $cookie\n";               		  
	$self->DebugAdd($PACKAGE."->CookieWrite()::Cookie Written".$cookie,3);
	
	return $cookie;
}

sub WriteScript{
	# print a javascript
	my($self,$script) = @_;
	if($script eq undef){ $script = $self->JS_Digest(); }
	my($result)= qq^\n<script type="text/javascript">\n<!--\n^ . $script . qq^//-->\n</script>\n^;
	return $result;
}

sub JS_Digest{
	my($self,%opts) = @_;

if($self->{digest} eq "MD5"){

return <<"ENDTAG"
/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you will usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_md5(s){ return binl2hex(core_md5(str2binl(s), s.length * chrsz));}
function b64_md5(s){ return binl2b64(core_md5(str2binl(s), s.length * chrsz));}
function str_md5(s){ return binl2str(core_md5(str2binl(s), s.length * chrsz));}
function hex_hmac_md5(key, data) { return binl2hex(core_hmac_md5(key, data)); }
function b64_hmac_md5(key, data) { return binl2b64(core_hmac_md5(key, data)); }
function str_hmac_md5(key, data) { return binl2str(core_hmac_md5(key, data)); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc") == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length
 */
function core_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);

}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Calculate the HMAC-MD5, of a key and some data
 */
function core_hmac_md5(key, data)
{
  var bkey = str2binl(key);
  if(bkey.length > 16) bkey = core_md5(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_md5(ipad.concat(str2binl(data)), 512 + data.length * chrsz);
  return core_md5(opad.concat(hash), 512 + 128);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert a string to an array of little-endian words
 * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
 */
function str2binl(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (i%32);
  return bin;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2str(bin)
{
  var str = "";
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < bin.length * 32; i += chrsz)
    str += String.fromCharCode((bin[i>>5] >>> (i % 32)) & mask);
  return str;
}

/*
 * Convert an array of little-endian words to a hex string.
 */
function binl2hex(binarray)
{
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((i%4)*8  )) & 0xF);
  }
  return str;
}

/*
 * Convert an array of little-endian words to a base-64 string
 */
function binl2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * ( i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * ((i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * ((i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}
ENDTAG

####################################################################
}else{	# $self->{digest} eq "Digest::SHA1"
####################################################################

return <<"ENDTAG"
/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you will usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_sha1(s){return binb2hex(core_sha1(str2binb(s),s.length * chrsz));}
function b64_sha1(s){return binb2b64(core_sha1(str2binb(s),s.length * chrsz));}
function str_sha1(s){return binb2str(core_sha1(str2binb(s),s.length * chrsz));}
function hex_hmac_sha1(key, data){ return binb2hex(core_hmac_sha1(key, data));}
function b64_hmac_sha1(key, data){ return binb2b64(core_hmac_sha1(key, data));}
function str_hmac_sha1(key, data){ return binb2str(core_hmac_sha1(key, data));}

/*
 * Perform a simple self-test to see if the VM is working
 */
function sha1_vm_test()
{
  return hex_sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
}

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
function core_hmac_sha1(key, data)
{
  var bkey = str2binb(key);
  if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
  return core_sha1(opad.concat(hash), 512 + 160);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert an 8-bit or 16-bit string to an array of big-endian words
 * In 8-bit function, characters >255 have their hi-byte silently ignored.
 */
function str2binb(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
  return bin;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2str(bin)
{
  var str = "";
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < bin.length * 32; i += chrsz)
    str += String.fromCharCode((bin[i>>5] >>> (32 - chrsz - i%32)) & mask);
  return str;
}

/*
 * Convert an array of big-endian words to a hex string.
 */
function binb2hex(binarray)
{
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
  }
  return str;
}

/*
 * Convert an array of big-endian words to a base-64 string
 */
function binb2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}
ENDTAG
####################################################################
}
####################################################################
}

1;
__END__

=pod

=head1 NAME

Digest::Auth - A perl library for web/network based authorization.

=head1 SYNOPSIS

Create a small CGI program:

	#!/usr/bin/perl -w
	use Digest::Auth;
	use CGI;

	use DBI;
	my $dsn = "DBI:mysql:database=mydatabase";
	my $user= "myuser";
	my $pass= "mypass";
	my $mydbh = DBI->connect($dsn,$user,$pass,{'RaiseError' => 1})

	my $Auth = Digest::Auth->new(dbh => $mydbh);

	my $result = $Auth->AutoAuth();

	print "Content-Type: text/html\n\n";

	if($result eq 1){
		print "user authorized";
	}else{
	  	print "user not authorized";  
	}

=head1 DESCRIPTION

This module attempts to provide a means for easily building a reasonably 
secure perl application using one way secure hash algorythms. This should 
not be a replacement for other security precautions such as SSL, SSH, etc. 
but instead an additional layer of protection to prevent common types of 
attacks which many perl applications are susceptable to.

This library idealy works in conjuction with client side hash algorythms to 
provide a much more secure method of athenticating users although you can 
opt to not use an client side hashing for the sake of compatibility.

This module is licensed under the GPL.  
See the LICENSE section below for more details.

=head1 MOTIVATION

Session based user access is key to nearly every internet and intranet 
application. While there have been a few attempts to make a secure hash 
login library they have had several short comings such as poor documentation, 
support, weak algoryms (such as MD5), a poor design, etc. This library 
seeks to fill an important gap to help make perl applications more secure. 

=head1 METHODS

This module is a programmer module and it makes a reasonable attempt to keep things 
safe and sanitized, however this is a module that is built with functionality in mind 
to keep things simple for programmers. One of the things I highly reccomend is that when 
you call this module after creating a link to your database handle, be sure to sanitize 
the data before it gets passed to this module. This means if you are using MySQL you 
should probably first make a database connection, and then if you are taking user input 
sanitize it with mysql_real_escape_string(). Within the module itself, it is using 
DBI::quote since we want to keep this module usable for multiple database types. I highly 
reccomend you look at the database you are utilizing and find whatever similair function 
is avalible for usage, and then use it properly.

=head2 new()

Declaring a new instance of Digest::Auth is easy.
  
Returns the value of the 'verbose' property.  When called with an
argument, it also sets the value of the property.  Use a true or false
Perl value, such as 1 or 0.

=head2 Put() and Get()

Digest::Auth keeps tabs on how long sessions are allowed to last. To change or set options 
you can use the Put() and Get() methods. Put takes one or multiple arguments as a Hash.
Get on the other hand takes single variable arguements.

	$Auth->Put(connection => 7200,
		       validation => 300,
		       idletime   => 600);

	# Find the value of Auth->{datamapping}{session}{table}
	my($CurrentValue) = $Auth->Get(datamapping,session,table);
	
	# Find the value of connection
	my($CurrentValue) = $Auth->Get(connection);

=item * dbh

Passes an open Database handel to the Digest::Auth perl module.

	# connect to a database
	use DBI;
	my $dsn = "DBI:mysql:database=mydatabase";
	my $user= "myuser";
	my $pass= "mypass";
	my $mydbh = DBI->connect($dsn,$user,$pass);

	$Auth->Put(dbh => $mydbh); # pass the database handel

=item * debug

Debug mode spews additional information. Use 1=on or 0=off. Default is off.

	$Auth->Put(debug => 1);

=item * domain

Domain name for cookie use. This leverages the browser domain usage conventions.

	$Auth->Put(domain => "."); # this is the default value (any domains)
	$Auth->Put(domain => ".avitar.net"); # specific domain
	$Auth->Put(domain => "secure.avitar.net"); # more specific domain convention

=item * usecookies

Use cookies to maintain sessions.

	$Auth->Put(usecookies => 0); # optional, puts the responsibility 
				     # on the programmer to carry session data
				     # this is the reccomended behavor for higher compatibility
				     # although it reduces ease of use.
					
	$Auth->Put(usecookies => 1); # default behaviour

=item * digest

Hash Digest to use
	
	$Auth->Put(domain => "Digest::SHA1");   # This is the default value
	$Auth->Put(domain => "MD5"); 		# Use the alternate MD5 hash algorythm
	$Auth->Put(domain => "My::New::Hash");  # Use an unknown hash type

	
=item * connection

Maximum total length of time a session is allowed to be. Default is 86400 seconds (24 hours). 
To disable change to -1. This will expire an active session if it exceedes this amout of time 
which helps to prevent some bot/macro'ed actions that would keep the user active indefinately. 
The user should be able to log back in afterwards immediatly. This combined with a Human Readable 
Identification code will keep people from abusing login times. For help with random text you can 
use the Keygen() method.

	$Auth->Put(connection => 7200);
	# Or 
	$Auth->Put(connection => -1); # change it to unlimited
	
=item * validation

Amount of time a user has to enter a username and password and submit it back to the 
server before their validation key becomes invalid. Default is 600 seconds (10 minutes). 
To disable change to -1.

	$Auth->Put(validation => 600); # change it to 5
	# Or 
	$Auth->Put(validation => -1); # change it to unlimited

=item * idletime

Amount of time a user has to idle in the system without their session expiring. Default 
time is 900 seconds (15 minutes). To disable change to -1.

	$Auth->Put(idletime => 3600); # change it to 60 minutes 
	# Or 
	$Auth->Put(idletime => -1); # change it to unlimited

=item * maxconperip

Maximum connections/sessions per IP address. Default is 10. For an unlimited number of 
sessions per IP address (Highly unreccomended) use the value of -1.

	$Auth->Put(maxconperip => 100); # change it to 100 connections	 
	# Or 
	$Auth->Put(maxconperip => -1); # change it to unlimited
	
=item * maxconperuser

Maximum connections/sessions per user name. Default is 10. For an unlimited number of 
sessions per IP address (Highly unreccomended) use the value of -1.

	$Auth->Put(maxconperuser => 10); # change it to 10	 
	# Or 
	$Auth->Put(maxconperuser => -1); # change it to unlimited

=item * maxbadpass

Maximum number of times a user can enter a bad password before they get banned/locked out. Default 
is 5. For an unlimited number of sessions per IP address (Highly unreccomended) use the 
value of -1.

	$Auth->Put(maxconperuser => 10); # change it to 10	 
	# Or 
	$Auth->Put(maxconperuser => -1); # change it to unlimited

=item * locklength

This determines how bans/locks for rule violations are handeled. In most cases you can just leave 
these as is. The ban length goes up with each additional rule violation that occours within 
the forgiverate. This is one of the trickier items to configure.

The defaults are: 5 min, then 15 min, then 1 hr, then 1 day, then permenent. You can add or remove 
levels in between each section if you want for the ban length rules. All times are in seconds, 
and you can use -1 for permenent. The library expects concurrently increasing ban lengths.

	# make all bans permenent
	$Auth->Put(banlength => [-1]); 

	# make all bans 1 h
	$Auth->Put(banlength => [3600]); r

	# change bans to 10 min, 2 hrs, 2 hrs, 2 hrs, then permenent.
	$Auth->Put(banlength => [900,7200,7200,7200,-1]); 

=item * forgiverate

This variable controls how long it takes for bad login attempts to expire. This is applies to loggin in 
on an invalid session hash, username, ip address, etc. 

	$Auth->Put(forgiverate	=> 86400);

=item * cookiename

This variable dertermines the name of the cookie that maintains user session credentials. In most cases you 
can leave it as is.

	$Auth->Put(cookiename => "MyCookieCert");	# Cookie name to use for authorization

=item * datamaping

Use this option if you are using this module with an existing user database. It allows you to modify the 
column names the module utilizes.

$Auth->Put(datamaping	=> 
       (session => {
		table		=> "session",
	        ip		=> "ip",
	        key		=> "key",
	        hash		=> "hash",
	        userid		=> "userid",
	        firstactive	=> "firstactive",
	        lastactive	=> "lastactive",
    	},
	sessionlocks => {
    		table		=> "sessionlocks",
	        ip		=> "ip",
	        stamp		=> "stamp",
	        key		=> "key",
	        hash		=> "hash",
	        userid		=> "userid",
        },	
	sessionattempts => {
 		table		=> "sessionattempts",
	        ip		=> "ip",
	        stamp		=> "stamp",
	        key		=> "key",
	        hash		=> "hash",
	        userid		=> "userid",
	},
	user => {		
                table		=> "user",
                userid		=> "userid",
                password	=> "password",
	},
	)
);  	
	
=head2 AutoAuth()

This is used to help automatically authorize an individual to further automate the 
login process. While this gives you less control of the login process, it does 
simplfy it by calling a single Method from the object as you walk through the login 
process.

=head2 Authorize()



=head2 TableMake()
=head2 Initialize()
=head2 Validate()

=head1 TODO

=item * Seperate the hash algorythm to a seperate sub module

Need to get the rights to put this up in CPAN from Pause.

=item * Allow hash selection 

Rather then dictating usage of the SHA1 exclusively, I wanted to allow different digest's to be
utilized. Eventually I will use a proto command to allow for any hash algorythm you want to use. 
Intinally I will stick to MD5 and SHA1 (default) 

=item * 
=item * 

=head1 AUTHOR

David Smith
dsmith@avitar.net
http://avitar.net

=head1 COPYRIGHT

Copyright 2007 Avitar.net.  All rights reserved.
All rights reserved.

You may freely distribute and/or modify this module under the terms of either the GNU 
General Public License (GPL) or the Artistic License, as specified in the Perl README 
file.

=cut
