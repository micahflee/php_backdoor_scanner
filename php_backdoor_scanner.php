<?php

// usage
if($argc < 3) {
    echo "[] Usage: php ".$argv[0]." folder_to_scan output_file [false_positives_file]\n\n";
    exit();
}
$target_dir = $argv[1];
$output_file = $argv[2];
if($argc == 4) {
    $false_positives_file = $argv[3];
    $contents = file_get_contents($false_positives_file);
    $false_positives = explode("\n", $contents);
} else {
    $false_positives = false;
}

// returns whether or not it's a php file
function is_php_file($filename) {
    return substr($filename, -4) == ".php" || 
        substr($filename, -5) == ".php4" || 
        substr($filename, -5) == ".php5";
}

// recursively scan a directory for malware
$dir_count = 0;
function backdoor_scan($path) {
    global $suspicious_strings;
    global $suspicious_files;
    global $output_file;
    global $false_positives;
    global $dir_count;
    
    echo ".";
    $dir_count++;
    
    // open directory
    $d = @dir($path);
    if($d == false) {
        echo "\n[] Failed to open directory ".$path.", skipping";
        return;
    }
    while(false !== ($filename = $d->read())) {
        // skip . and ..
        if($filename != "." && $filename != "..") {
            $full_filename = $d->path."/".$filename;
            
            // is it a false positive?
            $false = false;
            if($false_positives) {
                if(in_array($full_filename, $false_positives))
                    $false = true;
            }
            if(!$false) {
                // is it another directory?
                if(is_dir($full_filename)) {
                    // scan it
                    backdoor_scan($full_filename);
                } else {        
                    // is it a php file?
                    if(is_php_file($filename)) {
                        // scan this file
                        $contents = file_get_contents($full_filename);
                        $suspicious = false;
                        foreach($suspicious_strings as $string) {
                            if(strpos($contents, $string) != false)
                                $suspicious = true;
                        }
                        if($suspicious) {
                            // found a suspicious file!
                            echo "\n[] *** Suspicious file found: ".$full_filename;
                            
                            // record this in the output file
                            // note: i'm opening and closing this file each time so you can view the file before the entire scan is done
                            $of = fopen($output_file, "a");
                            fwrite($of, $full_filename."\n");
                            fclose($of);
                        }
                    }
                }
            }
        }
    }
}

// start with an empty output file
$of = fopen($output_file, "w");
fclose($of);

// files are suspicious if they contain any of these strings
$suspicious_strings = array('c99shell', 'phpspypass', 'Owned', 'hacker', 'h4x0r', '/etc/passwd', 'uname -a', 'eval(base64_decode(');

// if the target_dir has a trailing /, remove it
if(substr($target_dir, -1) == "/")
    $target_dir = substr($target_dir, 0, strlen($target_dir)-1);

// scan it all
backdoor_scan($target_dir);

// print out the suspicious files
echo "\n\n";
if(sizeof($suspicious_files > 0)) {
    echo "[] Scan complete. A list of suspicious files is stored in: ".$output_file."\n";
} else {
    echo "[] Scan complete. No suspicious files were found.";
}
echo "\n";

?>
