#
# Copyright (c) 2015 Daniel Reece - @HBRN8 - danielre@uk.ibm.com
#

class Wordpress_add_admin < BeEF::Core::Command

        def self.options
	    	return [{'name'=>'user', 'ui_label' => 'Username:', 'value' => 'beef'},	
		{'name'=>'pass', 'ui_label' => 'Pwd:', 'value' => [*('a'..'z'),*('0'..'9')].shuffle[0,8].join},
		{'name'=>'email', 'ui_label' => 'Email:', 'value' => ''},
		{'name'=>'domail', 'type' => 'checkbox', 'ui_label' => 'Success mail?:', 'checked' => 'true'},
		{'name'=>'url', 'ui_label' => 'Website:', 'value' => 'beefproject.com'},
		{'name'=>'fname', 'ui_label' => 'FirstName:', 'value' => 'beef'},
		{'name'=>'lname', 'ui_label' => 'LastName:', 'value' => 'project'}]
	end

  	def post_execute
  	end
  
end
