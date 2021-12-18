#include <cstring>
#include <errno.h>
#include <exception>
#include <grp.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <locale>
#include <memory>
#include <optional>
#include <pwd.h>
#include <regex>
#include <set>
#include <sstream>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
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
#define LOG_DEBUG_VARIABLE(variable) BOOST_LOG_TRIVIAL(debug) << #variable << "=" << (variable);
#define VARIABLE_OUT(variable) #variable << "=" << (variable)

namespace fs = std::filesystem; // @suppress("Symbol is not resolved")
namespace po = boost::program_options;
namespace logging = boost::log;

using std::list;
using std::runtime_error;
using std::map;
using std::regex;
using std::set;
using std::string;
using std::vector;

class UserException : public runtime_error {
public:
    UserException(const string &what) : runtime_error(what) { }
};

class ConfigException : public runtime_error {
public:
    ConfigException(const string &what) : runtime_error(what) { }
};

class SubprocessException : public runtime_error {
public:
    SubprocessException(const string &what) : runtime_error(what) { }
};


class User {
public:
    string user;
    set<string> groups;
    User(const string &user, const set<string> &groups) :
        user(user), groups(groups) {
    }
    User() {
    }
    static User get_current_user();
};

class ConfigSection {
public:
    set<string> admin_users;
    set<string> admin_groups;
    string name_prefix;
    string base_dir;
    int max_name_length = -1;

    ConfigSection() {
    }

    void use_defaults(const ConfigSection &defaults) {
        this->name_prefix = defaults.name_prefix;
        this->base_dir = defaults.base_dir;
        this->max_name_length = defaults.max_name_length;
        this->admin_users = defaults.admin_users;
        this->admin_groups = defaults.admin_groups;
    }

};

class ConfigOptions {
public:
    string user_add_application;
};

class Config {
public:
    ConfigOptions options;
    ConfigSection defaults;
    vector<ConfigSection> sections;
    Config() { }
    Config (const YAML::Node &node);

    const ConfigSection&
    get_coinfig_section (const string &prefix);

    inline static const string CONFIG_OPTIONS = "options";
    inline static const string CONFIG_USER_ADD = "user_add";
    inline static const string CONFIG_APPLICATION = "application";
    inline static const string CONFIG_DEFAULTS = "defaults";
    inline static const string CONFIG_CONFIGS = "configs";
    inline static const string CONFIG_ADMINISTRATORS = "administrators";
    inline static const string CONFIG_USERS = "users";
    inline static const string CONFIG_GROUPS = "groups";
    inline static const string CONFIG_NAME_PREFIX = "name_prefox";
    inline static const string CONFIG_BASE_DIR = "base_dir";
    inline static const string CONFIG_MAX_NAME_LENGTH = "max_name_length";
    inline static const int DEFAULT_MAX_NAME_LENGTH = 25;
    inline static const string DEFAULT_BASE_DIR = "/home";
    inline static const string DEFAULT_NAME_PREFIX = "";
    inline static const string DEFAULT_USER_ADD_APPLICATION = "/usr/bin/useradd";
private:
    ConfigSection
    parse_config_section (const YAML::Node &node, bool parse_defaults = false);
};

User User::get_current_user() {
    char *user_name_str = getlogin();
    if(user_name_str == nullptr) {
        string error_message =
            "No user login found. errno=" +
            std::to_string(errno);
        throw UserException(error_message);
    }
    string user_name(getlogin());
    BOOST_LOG_TRIVIAL(debug) << "Current user: " << user_name;
    User result_user = User();
    result_user.user = user_name;
    uid_t user_id = getuid();
    passwd *pwd = getpwuid(user_id);
    group *gr;
    if(pwd == nullptr) {
        BOOST_LOG_TRIVIAL(error) << "User group not found";
        return result_user;
    }
    gid_t group_id = pwd->pw_gid;

    int groups_status;
    int ngroups = 1;
    gid_t *groups_arr = new gid_t[ngroups];
    do {
        BOOST_LOG_TRIVIAL(debug) << "Before: " << VARIABLE_OUT(ngroups);
        // LOG_DEBUG_VARIABLE(ngroups);
        delete[] groups_arr;
        groups_arr = new gid_t[ngroups];
        groups_status =
            getgrouplist(user_name.c_str(), group_id, groups_arr, &ngroups);
        BOOST_LOG_TRIVIAL(debug) << "After:" << VARIABLE_OUT(ngroups) << ", " << VARIABLE_OUT(groups_status);
    } while(groups_status == -1);
    set<gid_t> group_ids(groups_arr, groups_arr + ngroups);
    delete[] groups_arr;
    for(set<gid_t>::iterator gr_iter = group_ids.begin();
        gr_iter != group_ids.end();
        ++gr_iter) {

        gr = getgrgid(*gr_iter);
        if(gr != nullptr) {
            result_user.groups.insert(gr->gr_name);
        }
    }
    return result_user;
}

Config::Config(const YAML::Node &node) {

    this->defaults.base_dir = DEFAULT_BASE_DIR;
    this->defaults.max_name_length = DEFAULT_MAX_NAME_LENGTH;
    this->defaults.name_prefix = DEFAULT_NAME_PREFIX;

    bool have_user_add_application = false;
    if(node[CONFIG_OPTIONS] and node[CONFIG_OPTIONS][CONFIG_USER_ADD]) {
        YAML::Node user_add_node = node[CONFIG_OPTIONS][CONFIG_USER_ADD];
        if(user_add_node[CONFIG_APPLICATION]) {
            this->options.user_add_application =
                    user_add_node[CONFIG_APPLICATION].as<string>();
            have_user_add_application = true;
        }
    }
    if(!have_user_add_application) {
        this->options.user_add_application = DEFAULT_USER_ADD_APPLICATION;
    }

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

ConfigSection Config::parse_config_section(const YAML::Node &node,
                                           bool parse_defaults) {
    ConfigSection section;

    if(!parse_defaults) {
        section.use_defaults(this->defaults);
    }

    bool with_administrators = false;

    map<string, set<string> ConfigSection::*> acl_fields {
        {CONFIG_USERS, &ConfigSection::admin_users},
        {CONFIG_GROUPS, &ConfigSection::admin_groups}
    };
    if (node[CONFIG_ADMINISTRATORS]) {
        YAML::Node administrators = node[CONFIG_ADMINISTRATORS];
        for (const auto& [field_name, field] : acl_fields) {
            if (administrators[field_name]) {
                (section.*field).clear();
                YAML::Node acl_node = administrators[field_name];
                for (YAML::const_iterator acl_iter = acl_node.begin ();
                        acl_iter != acl_node.end (); ++acl_iter) {
                    string acl_element_name = acl_iter->as<string>();
                    (section.*field).insert(acl_element_name);
                    with_administrators = true;
                }
            }
        }
    }

    map<string, string ConfigSection::*> string_fields {
        { CONFIG_NAME_PREFIX, &ConfigSection::name_prefix },
        { CONFIG_BASE_DIR, &ConfigSection::base_dir }
    };
    for(const auto& [field_name, field] : string_fields) {
        if(node[field_name]) {
            YAML::Node string_node = node[field_name];
            section.*field = node[field_name].as<string>();
        }
    }

    map<string, int ConfigSection::*> int_fields {
        { CONFIG_MAX_NAME_LENGTH, &ConfigSection::max_name_length }
    };
    for(const auto& [field_name, field] : int_fields) {
        if(node[field_name]) {
            YAML::Node int_node = node[field_name];
            section.*field = node[field_name].as<int>();
        }
    }

    return section;
}

const string CONFIG_FILE_NAME = "restrictedusermanager.yaml";
const string CONFIG_DIRS[] = {"/usr/local/etc", "/etc"};
const auto RE_USER_NAME = std::regex("^[a-z][0-9a-z_-]+$");

bool simulation_mode = true;

Config config;

boost::optional<YAML::Node>
load_config()
{
    boost::optional<YAML::Node> config_node;
    BOOST_LOG_TRIVIAL(debug) << "Load configuration file";
    string config_file_full_name;
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
    config = Config(node);
}

bool
is_valid_user_name(const string &user_name)
{
    return regex_match(user_name, RE_USER_NAME);
}

vector<string>
user_add_options(const string &user_name, const string &base_dir)
{
    return vector<string> { "-b", base_dir, user_name };
}

void log_debug_execv(const char *app, char * const proc_argv[]) {
    std::stringstream ss;
    ss << "Run application: " << string(app) << " with arguments: [";

    bool is_not_first;
    const char * arg_ptr;
    for(arg_ptr = proc_argv[0], is_not_first = false;
            arg_ptr != nullptr;
            ++arg_ptr, is_not_first = true) {
        if(is_not_first) {
            ss << ", ";
        }
        ss << string(arg_ptr);
    }
    ss << "]";
    BOOST_LOG_TRIVIAL(debug) << ss.str();
}

void
run_user_add(const string &user_name, const string &base_dir = Config::DEFAULT_BASE_DIR) {
    BOOST_LOG_TRIVIAL(debug) << "run_user_add: " <<
            VARIABLE_OUT(user_name) << ", " << VARIABLE_OUT(base_dir);

    pid_t pid = fork();
    if(pid < 0) {
        throw SubprocessException("Can't call fork().");
    } else if(pid == 0) {
        BOOST_LOG_TRIVIAL(debug) << "In the subprocess.";
        string user_add_app = config.options.user_add_application;
        string app_filename = fs::path(user_add_app).filename(); // @suppress("Invalid arguments") // @suppress("Function cannot be resolved") // @suppress("Method cannot be resolved")
        vector<string> proc_argv_vector { app_filename };
        vector<string> app_options = user_add_options(user_name, base_dir);
        proc_argv_vector.insert(proc_argv_vector.end(), app_options.begin(), app_options.end());
        size_t arg_count = proc_argv_vector.size();
        char *proc_argv[arg_count + 1];
        for(size_t i = 0; i < arg_count; ++i) {
            size_t char_count = proc_argv_vector[i].length();
            proc_argv[i] = new char[char_count];
            std::strcpy(proc_argv[i], proc_argv_vector[i].c_str());
        }
        proc_argv[arg_count] = nullptr;

        log_debug_execv(user_add_app.c_str(), proc_argv);
        if(simulation_mode) {
            BOOST_LOG_TRIVIAL(info) << "Simulation mode. The user was not be created.";
        } else {
            execv(user_add_app.c_str(), proc_argv);
        }

        _exit(EXIT_FAILURE);
    } else {
        BOOST_LOG_TRIVIAL(debug) << "In the main process.";
        int wstatus;
        pid_t wait_pid = waitpid(pid, &wstatus, 0);
        if(WIFEXITED(wstatus) and WEXITSTATUS(wstatus) == EXIT_SUCCESS) {
            BOOST_LOG_TRIVIAL(debug) <<
                    "Subprocess for user adding was exiting successfully."; // TODO check
        } else {
            throw SubprocessException("Subprocess for user adding was exited with error"); // TODO check
        }
    }
}

const ConfigSection*
get_config_section_by_user_name(const string &user_name)
{
    for (size_t config_section_idx = 0;
            config_section_idx < config.sections.size();
            ++config_section_idx) {
        unsigned long int prefix_size =
                config.sections[config_section_idx].name_prefix.length();
        if (prefix_size > user_name.length()) {
            continue;
        }
        if (config.sections[config_section_idx].name_prefix.compare(
                0, prefix_size, user_name, 0, prefix_size) == 0) {
            return &config.sections[config_section_idx];
        }
    }
    return nullptr;
}

bool check_authentication(const User &user, const ConfigSection &config_section) {
    BOOST_LOG_TRIVIAL(debug) << "Check authentication.";
    if(config_section.admin_users.find(user.user) !=
            config_section.admin_users.end()) {
        BOOST_LOG_TRIVIAL(debug) << "Access accepted for user " << user.user << ".";
        return true;
    } else {
        for(const auto group : user.groups) {
            if(config_section.admin_groups.find(group) !=
                    config_section.admin_groups.end()) {
                BOOST_LOG_TRIVIAL(debug) <<
                        "Access accepted for group " << group << ".";
                return true;
            }
        }
    }
    BOOST_LOG_TRIVIAL(debug) << "Access denied.";
    return false;
}

bool add_user(const string &user_name) {
    BOOST_LOG_TRIVIAL(debug) << "Add user " << user_name;
    if(!is_valid_user_name(user_name)) {
        BOOST_LOG_TRIVIAL(error) << "The username " << user_name << " is not valid.";
    }
    User current_user = User::get_current_user();
    const ConfigSection *config_section = get_config_section_by_user_name(user_name);
    if(config_section == nullptr) {
        BOOST_LOG_TRIVIAL(error) << "Config section for username " << user_name << " not found.";
        return false;
    }
    if(!check_authentication(current_user, *config_section)) {
        BOOST_LOG_TRIVIAL(error) << "Access denied for creating the user " << user_name << ".";
        return false;
    }
    try {
        run_user_add(user_name);
    } catch(const SubprocessException &e) {
        BOOST_LOG_TRIVIAL(error) << "User was not be created by the reason: " << e.what();
        return false;
    }
    return true;
}

int main(int argc, char **argv) {
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
    po::options_description desc(_("Available options"));
    desc.add_options()
        ("help,h", _("Show help."))
        ("add-user,a", po::value<string>(), _("Add user"))
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
        string user_name = vm["add-user"].as<string>();
        add_user(user_name);
    }

    return EXIT_SUCCESS;
}
