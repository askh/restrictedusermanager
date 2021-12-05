#include <iostream>
#include <locale>
#include <string>
#include <vector>
#include <boost/optional.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/option.hpp>
#include <boost/program_options/options_description.hpp>
#include <yaml-cpp/yaml.h>
#include "gettext.h"
#include "../config.h"

#define _(string) gettext(string)

namespace po = boost::program_options;

const std::string CONFIG_FILE_NAME = "restrictedusermanager.cpp";
const std::string CONFIG_DIRS[] = {"/usr/local/etc", "/etc"};

int main(int argc, char **argv) {
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	po::options_description desc("Available options");
	desc.add_options()
        ("help,h", "Show help.")
		("add-user,a", po::value<std::string>(), "Add user");
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if(vm.count("help")) {
    	std::cout << desc << "\n";
    	return 0;
    }

    if(vm.count("add-user")) {
    	std::string user_name = vm["add-user"].as<std::string>();
    	std::cout << user_name << "\n";
    }

	return 0;
}
