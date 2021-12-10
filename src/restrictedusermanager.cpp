#include <errno.h>
#include <exception>
#include <grp.h>
#include <iostream>
#include <fstream>
#include <locale>
#include <optional>
#include <pwd.h>
#include <set>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <boost/optional.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/option.hpp>
#include <boost/program_options/options_description.hpp>
#include <yaml-cpp/yaml.h>
#include "gettext.h"
#include "../config.h"

#define _(string) gettext(string)

namespace po = boost::program_options;
namespace logging = boost::log;

class UserException : public std::runtime_error {
public:
    UserException(const std::string &what) : std::runtime_error(what) { }
};

class ConfigException : public std::runtime_error {
public:
    ConfigException(const std::string &what) : std::runtime_error(what) { }
};

class User {
public:
    std::string user;
    std::set<std::string> groups;
    User(const std::string &user, const std::set<std::string> &groups) :
        user(user), groups(groups) {
    }
    User() {
    }
    static User get_current_user();
};

class ConfigSection {
public:
    std::set<std::string> users;
    std::set<std::string> groups;
    std::string name_prefix;
    std::string home_dir;
    unsigned int max_name_length = -1;

    ConfigSection() {
    }

    void use_defaults(const ConfigSection &defaults) {
        this->name_prefix = defaults.name_prefix;
        this->home_dir = defaults.home_dir;
        this->max_name_length = defaults.max_name_length;
    }

    /*
    void add_defaults(const ConfigSection &defaults) {
        if(this->name_prefix.empty()) {
            this->name_prefix = defaults.name_prefix;
        }
        if(this->home_dir.empty()) {
            this->home_dir = defaults.home_dir;
        }
        if(this->max_name_length < 0) {
            this->max_name_length = defaults.max_name_length;
        }
    }
    */

};

class Config {
public:
    Config (const YAML::Node &node);
    const ConfigSection&
    get_coinfig_section (const std::string &prefix);
    inline static const std::string CONFIG_DEFAULTS = "defaults";
    inline static const std::string CONFIG_CONFIGS = "configs";
    inline static const std::string CONFIG_ADMINISTRATORS = "administrators";
    inline static const std::string CONFIG_USERS = "users";
    inline static const std::string CONFIG_GROUPS = "groups";
    inline static const std::string CONFIG_NAME_PREFIX = "name_prefox";
    inline static const std::string CONFIG_HOME_DIR = "home_dir";
    inline static const int DEFAULT_MAX_NAME_LENGTH = 25;
    inline static const std::string DEFAULT_HOME_DIR = "/home";
    inline static const std::string DEFAULT_NAME_PREFIX = "";
private:
    ConfigSection defaults;
    std::vector<ConfigSection> sections;

    ConfigSection
    parse_config_section (const YAML::Node &node, bool parse_defaults = false);
};

User User::get_current_user() {
    char *user_name_str = getlogin();
    if(user_name_str == NULL) {
        std::string error_message =
            "No user login found. errno=" +
            std::to_string(errno);
        throw UserException(error_message);
    }
    std::string user_name(getlogin());
    BOOST_LOG_TRIVIAL(debug) << "Current user: " << user_name;
    User result_user = User();
    result_user.user = user_name;
    uid_t user_id = getuid();
    passwd *pwd = getpwuid(user_id);
    group *gr;
    if(pwd == NULL) {
        BOOST_LOG_TRIVIAL(error) << "User group not found";
        return result_user;
    }
    gid_t group_id = pwd->pw_gid;

    int groups_status;
    int ngroups = 2;
    gid_t *groups_arr;
    do {
        BOOST_LOG_TRIVIAL(debug) << "ngroups=" << ngroups;
        groups_arr = new gid_t[ngroups];
        groups_status =
            getgrouplist(user_name.c_str(), group_id, groups_arr, &ngroups);
    } while(groups_status != -1);
    std::set<gid_t> group_ids(groups_arr, groups_arr + ngroups);
    delete[] groups_arr;
    for(std::set<gid_t>::iterator gr_iter = group_ids.begin();
        gr_iter != group_ids.end();
        ++gr_iter) {

        gr = getgrgid(*gr_iter);
        if(gr != NULL) {
            result_user.groups.insert(gr->gr_name);
        }
    }
    return result_user;
}

Config::Config(const YAML::Node &node) {

    this->defaults.home_dir = DEFAULT_HOME_DIR;
    this->defaults.max_name_length = DEFAULT_MAX_NAME_LENGTH;
    this->defaults.name_prefix = DEFAULT_NAME_PREFIX;

    if(node[CONFIG_DEFAULTS]) {
        this->defaults = parse_config_section(node[CONFIG_DEFAULTS], true);
    }

    if(node[CONFIG_CONFIGS]) {
        YAML::Node configs = node[CONFIG_CONFIGS];
        for(YAML::const_iterator iter = configs.begin(); iter != configs.end(); ++iter) {
            this->sections.push_back(parse_config_section(*iter));
        }
    }
}

template <typename T> class ConfigSectionField {
public:
    std::string name;
    T ConfigSection::* field;
    ConfigSectionField(const std::string &name, T ConfigSection::* field) :
        name(name), field(field) { }
};

ConfigSection Config::parse_config_section(const YAML::Node &node,
                                           bool parse_defaults) {

    ConfigSection section;
    ConfigSectionField<std::set<std::string>> acl_fields[] = {
        ConfigSectionField<std::set<std::string>>(CONFIG_USERS,
                &ConfigSection::users),
        ConfigSectionField<std::set<std::string>>(CONFIG_GROUPS,
                &ConfigSection::groups)
    };
    const size_t acl_fields_count =
            sizeof(acl_fields) /
            sizeof(ConfigSectionField<std::set<std::string>>);
    if(!parse_defaults) {
        section.use_defaults(this->defaults);
    }
    bool with_administrators = false;
    if (node[CONFIG_ADMINISTRATORS]) {
        YAML::Node administrators = node[CONFIG_ADMINISTRATORS];
        for (size_t acl_field_idx = 0; acl_field_idx < acl_fields_count;
                ++acl_field_idx) {
            const std::string field_name = acl_fields[acl_field_idx].name;
            std::set<std::string> ConfigSection::*field =
                    acl_fields[acl_field_idx].field;
            if (administrators[field_name]) {
                YAML::Node acl_node = administrators[field_name];
                for (YAML::const_iterator acl_iter = acl_node.begin ();
                        acl_iter != acl_node.end (); ++acl_iter) {

                    std::string acl_element_name = acl_iter->as<std::string>();
                    (section.*field).insert (acl_element_name);
                }
            }
        }
    }

    ConfigSectionField<std::string> string_fields[] = {
        ConfigSectionField<std::string>(CONFIG_NAME_PREFIX,
                                        &ConfigSection::name_prefix),
        ConfigSectionField<std::string>(CONFIG_HOME_DIR,
                                        &ConfigSection::home_dir)
    };
    const size_t string_field_count =
            sizeof(string_fields) / sizeof(std::string);
    for(size_t string_field_idx = 0;
            string_field_idx < string_field_count; ++string_field_idx) {



    }

    if(!parse_defaults && !with_administrators) {
        BOOST_LOG_TRIVIAL(debug) << "Config section without administrators";
    }


    return section;
}

const std::string CONFIG_FILE_NAME = "restrictedusermanager.cpp";
const std::string CONFIG_DIRS[] = {"/usr/local/etc", "/etc"};

bool simulation_mode = true;

boost::optional<YAML::Node>
load_config()
{
    boost::optional<YAML::Node> config_node;
    BOOST_LOG_TRIVIAL(debug) << "Load configuration file";
    std::string config_file_full_name;
    const size_t config_dir_count = sizeof(CONFIG_DIRS)
            / sizeof(CONFIG_DIRS[0]);
    bool config_found = false;
    for (size_t config_dir_idx = 0; config_dir_idx < config_dir_count;
            ++config_dir_idx) {
        config_file_full_name = CONFIG_DIRS[config_dir_idx] + "/"
                + CONFIG_FILE_NAME;
        try {
            std::ifstream file (config_file_full_name);
            file.close ();
            config_found = true;
            break;
        }
        catch (...) {
            BOOST_LOG_TRIVIAL(debug)
            << "Can't read file " << config_file_full_name;
        }
    }
    if (!config_found) {
        return boost::none;
    }
    try {
        config_node = YAML::LoadFile (config_file_full_name);
    }
    catch (...) {
        BOOST_LOG_TRIVIAL(error)
        << "Can't load file " << config_file_full_name;
        return boost::none;
    }
    return boost::optional<YAML::Node> (config_node);
}

void set_config(const YAML::Node &node) {

}

void add_user(const std::string &user_name) {
    BOOST_LOG_TRIVIAL(debug) << "Add user " << user_name;
    User current_user = User::get_current_user();



}

int main(int argc, char **argv) {
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
    po::options_description desc(_("Available options"));
    desc.add_options()
        ("help,h", _("Show help."))
        ("add-user,a", po::value<std::string>(), _("Add user"))
        ("verbose,v", _("Verbose mode"))
        ("simulate,S", _("Simulation mode (doesn't do real work)"));
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if(vm.count("help")) {
        std::cout << desc << "\n";
        return EXIT_SUCCESS;
    }

    if(vm.count("verbose")) {
        logging::core::get()->set_filter // @suppress("Invalid arguments")
        (
            logging::trivial::severity >= logging::trivial::debug // @suppress("Symbol is not resolved")
        );
    }
    if(!vm.count("simulate")) {
        simulation_mode = false;
    }
    BOOST_LOG_TRIVIAL(debug) << "Simulation mode: " << simulation_mode;

    boost::optional<YAML::Node> config_node = load_config();

    if(!config_node) {
        BOOST_LOG_TRIVIAL(error) << "Config file not available. Nothing has been done.";
        return EXIT_FAILURE;
    } else {
        set_config(*config_node);
    }

    if(vm.count("add-user")) {
        std::string user_name = vm["add-user"].as<std::string>();
        add_user(user_name);
    }

    return EXIT_SUCCESS;
}
