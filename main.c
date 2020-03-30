#include "minivcs.h"

#include <CEasyException/exception.h>
#include <CTransform/crypto/mem_cleanse.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <zconf.h>
#include <stdlib.h>

/*
 * minivcs config ...
 *  minivcs config generate [project_path]
 *  minivcs config list [project_path]
 *  minivcs config get <key> [project_path]
 *  minivcs config set <key> <value> [project_path]
 *
 * minivcs project ...
 *  minivcs project init [project_path]
 *  minivcs project init -d [project_path]
 *
 * minivcs branch ...
 *  minivcs branch list [project_path]
 *  minivcs branch add branch_name [project_path]
 *  minivcs branch add -f branch_name [project_path]
 *  minivcs branch delete branch_name [project_path]
 *  minivcs branch delete -y branch_name [project_path]
 *  minivcs branch store branch_name data_path [project_path]
 *  minivcs branch store -n branch_name data_path [project_path]
 *  minivcs branch store -y branch_name data_path [project_path]
 *  minivcs branch extract branch_name data_path [project_path]
 */

typedef struct option
{
    const char opt;
    const char* description;
} option;

typedef struct command
{
    const char* command_str;
    const char* args;
    const option** options;
    const char* description;
    void (*func)(int argc, char** argv);
} command;

typedef struct subcommand
{
    const char* command_str;
    const struct command** cmds;
} subcommand;

const option  cli_project_init_opt_d = {'d', "Initialize with default config"};
const option  cli_branch_add_opt_f = {'f', "Overwrite existing branch"};
const option  cli_branch_delete_opt_y = {'y', "Automatically confirm branch deletion"};
const option  cli_branch_store_opt_n = {'n', "Create a new branch with provided content"};
const option  cli_branch_store_opt_y = {'y', "Automatically confirm branch changes"};

const option*  cli_config_generate_opts[] = {NULL};
const option*  cli_config_list_opts[] = {NULL};
const option*  cli_config_get_opts[] = {NULL};
const option*  cli_config_set_opts[] = {NULL};
const option*  cli_project_init_opts[] = {&cli_project_init_opt_d, NULL};
const option*  cli_branch_list_opts[] = {NULL};
const option*  cli_branch_add_opts[] = {&cli_branch_add_opt_f, NULL};
const option*  cli_branch_delete_opts[] = {&cli_branch_delete_opt_y, NULL};
const option*  cli_branch_store_opts[] = {&cli_branch_store_opt_n, &cli_branch_store_opt_y, NULL};
const option*  cli_branch_extract_opts[] = {NULL};

void cli_config_generate(int argc, char** argv);
void cli_config_list(int argc, char** argv);
void cli_config_get(int argc, char** argv);
void cli_config_set(int argc, char** argv);
void cli_project_init(int argc, char** argv);
void cli_branch_list(int argc, char** argv);
void cli_branch_add(int argc, char** argv);
void cli_branch_delete(int argc, char** argv);
void cli_branch_store(int argc, char** argv);
void cli_branch_extract(int argc, char** argv);

#define GEN_CMD(name, str, args, description)\
command cli_##name##_cmd = {str, args, cli_##name##_opts, description, cli_##name}

GEN_CMD(config_generate, "generate", NULL, "Generate a default config file for a project");
GEN_CMD(config_list, "list", NULL, "List all options from config file");
GEN_CMD(config_get, "get", "option", "Get value of an option");
GEN_CMD(config_set, "set", "option value", "Set an option value");
GEN_CMD(project_init, "init", NULL, "Initialize new project based on a config file");
GEN_CMD(branch_list, "list", NULL, "List all branches of a project");
GEN_CMD(branch_add, "add", "branch_name", "Create an empty branch");
GEN_CMD(branch_delete, "delete", "branch_name", "Delete branch");
GEN_CMD(branch_store, "store", "branch_name file_directory", "Store files to branch");
GEN_CMD(branch_extract, "extract","branch_name file_directory", "Extract files from branch");

const command* cli_config_cmds[] = {&cli_config_generate_cmd, &cli_config_list_cmd, &cli_config_get_cmd,
                                    &cli_config_set_cmd, NULL};
const command* cli_project_cmds[] = {&cli_project_init_cmd, NULL};
const command* cli_branch_cmds[] = {&cli_branch_list_cmd, &cli_branch_add_cmd, &cli_branch_delete_cmd,
                                    &cli_branch_store_cmd, &cli_branch_extract_cmd, NULL};

const subcommand cli_config_cmd = {"config", cli_config_cmds};
const subcommand cli_project_cmd = {"project", cli_project_cmds};
const subcommand cli_branch_cmd = {"branch", cli_branch_cmds};

const subcommand* cli_cmds[] = {&cli_config_cmd, &cli_project_cmd, &cli_branch_cmd, NULL};

const char* help_cmd = "help";

void print_help(const char* name)
{
    printf("%s command arguments [project_path | config_path]\n", name);
    printf("\tIf [project_path | config_path] is omitted, project from working directory will be used\n");
    printf("\n");
    for(const subcommand** scmd = cli_cmds; *scmd != NULL; ++scmd)
    {
        printf("%s %s ...\n", name, (*scmd)->command_str);
        for(const command** cmd = (*scmd)->cmds; *cmd != NULL; ++cmd)
        {
            if((*cmd)->args)
            {
                printf("\t%s %s: %s\n", (*cmd)->command_str, (*cmd)->args, (*cmd)->description);
            }
            else
            {
                printf("\t%s: %s\n", (*cmd)->command_str, (*cmd)->description);
            }
            for(const option** opt = (*cmd)->options; *opt != NULL; ++opt)
            {
                printf("\t\t-%c: %s\n", (*opt)->opt, (*opt)->description);
            }
        }
        printf("\n");
    }
    printf("%s %s: print this message and exit\n", name, help_cmd);
}

const char* def_proj_path = ".";

int get_not_option(int argc, char** argv, int size, const char** opts)
{
    int cnt = 0;
    bool all = false;
    for(int i = 1; i < argc && cnt < size; ++i)
    {
        if(argv[i][0] != '-' || all)
        {
            opts[cnt] = argv[i];
            ++cnt;
        }
        else if(strcmp(argv[i], "--") == 0)
        {
            all = true;
        }
    }
    return cnt;
}

char password[LINE_MAX + 1];

void set_password(struct minivcs_project* project)
{
    if(minivcs_need_password(project))
    {
        printf("Input project password: ");
        struct termios term, saved;
        if(tcgetattr(fileno(stdin), &term) < 0)
        {
            EXCEPTION_THROW(errno, "%s", "Failed to get user password");
            return;
        }
        if(tcgetattr(fileno(stdin), &saved) < 0)
        {
            EXCEPTION_THROW(errno, "%s", "Failed to get user password");
            return;
        }

        term.c_lflag &= ~(ICANON | ECHO);	/* Clear ICANON and ECHO. */
        term.c_cc[VMIN] = 1;
        term.c_cc[VTIME] = 0;
        if(tcsetattr(fileno(stdin), TCSANOW, &term) < 0)
        {
            EXCEPTION_THROW(errno, "%s", "Failed to get user password");
            return;
        }

        if(fgets(password, sizeof(password) - 1, stdin) == NULL)
        {
            tcsetattr(fileno(stdin), TCSANOW, &saved);
            EXCEPTION_THROW(errno, "%s", "Failed to get user password");
            return;
        }

        minivcs_set_password(password, project);

        if(tcsetattr(fileno(stdin), TCSANOW, &saved) < 0)
        {
            EXCEPTION_THROW(errno, "%s", "Failed to get user password");
            return;
        }
        printf("\n");
    }
}

bool prompt_yes_no()
{
    char ans[10];
    if(fgets(ans, sizeof(ans) - 1, stdin) == NULL)
    {
        return false;
    }
    if(ans[strlen(ans) - 1] == '\n')
    {
        ans[strlen(ans) - 1] = '\0';
    }
    return strcmp(ans, "y") == 0 || strcmp(ans, "Y") == 0 || strcmp(ans, "yes") == 0 || strcmp(ans, "Yes") == 0;
}

void cli_config_generate(int argc, char** argv)
{
    const char* path = def_proj_path;
    get_not_option(argc, argv, 1, &path);
    minivcs_generate_config(path);
}

void cli_config_list(int argc, char** argv)
{
    const char* path = def_proj_path;
    get_not_option(argc, argv, 1, &path);
    struct config conf;
    minivcs_read_config_only(path, &conf);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }
    config_print(stdout, &conf);

    cleanup:
    config_destroy(&conf);
}

void cli_config_get(int argc, char** argv)
{
    const char* args[2];
    args[1] = def_proj_path;
    if(get_not_option(argc, argv, 2, args) < 1)
    {
        EXCEPTION_THROW(EINVAL, "%s", "Command requires arguments");
        return;
    }
    struct config conf;
    minivcs_read_config_only(args[1], &conf);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    const char* ret = config_get(args[0], &conf);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }
    if(!ret)
    {
        EXCEPTION_THROW(EINVAL, "Option \"%s\" does not exist", args[0]);
        goto cleanup;
    }

    printf("%s", ret);

    cleanup:
    config_destroy(&conf);
}

void cli_config_set(int argc, char** argv)
{
    const char* args[3];
    args[2] = def_proj_path;
    if(get_not_option(argc, argv, 3, args) < 2)
    {
        EXCEPTION_THROW(EINVAL, "%s", "Command requires arguments");
        return;
    }
    struct config conf;
    minivcs_read_config_only(args[2], &conf);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    config_set(args[0], args[1], &conf);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    config_save(&conf);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    cleanup:
    config_destroy(&conf);
}

void cli_project_init(int argc, char** argv)
{
    const char* path = def_proj_path;
    get_not_option(argc, argv, 1, &path);
    int opt;
    while((opt = getopt(argc, argv, "d"))!= -1)
    {
        if(opt == 'd')
        {
            minivcs_generate_config(path);
            if(EXCEPTION_IS_THROWN)
            {
                return;
            }
        }
    }
    struct minivcs_project proj;
    minivcs_read_config(path, &proj);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    set_password(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    minivcs_init_from_config(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    cleanup:
    minivcs_destroy(&proj);
}

void cli_branch_list(int argc, char** argv)
{
    const char* path = def_proj_path;
    get_not_option(argc, argv, 1, &path);
    struct minivcs_project proj;
    minivcs_read_config(path, &proj);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    set_password(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    minivcs_open_from_config(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    size_t count = branch_index_count(&proj.index);
    const char** branches = malloc(count * sizeof(const char*));
    if(!branches)
    {
        EXCEPTION_THROW_NOMSG(errno);
        goto cleanup;
    }
    branch_index_get_names(branches, &proj.index);
    for(size_t i = 0; i < count; ++i)
    {
        printf("%s", branches[i]);
    }
    free(branches);

    cleanup:
    minivcs_destroy(&proj);
}

void cli_branch_add(int argc, char** argv)
{
    const char* args[2];
    args[1] = def_proj_path;
    if(get_not_option(argc, argv, 2, args) < 1)
    {
        EXCEPTION_THROW(EINVAL, "%s", "Command requires arguments");
        return;
    }
    struct minivcs_project proj;
    minivcs_read_config(args[1], &proj);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    set_password(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    minivcs_open_from_config(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    if(branch_index_find(args[0], &proj.index))
    {
        bool force = false;
        int opt;
        while((opt = getopt(argc, argv, "f")) != -1)
        {
            if(opt == 'f')
            {
                force = true;
                break;
            }
        }
        if(force)
        {
            minivcs_delete_branch(args[0], &proj);
            if(EXCEPTION_IS_THROWN)
            {
                goto cleanup;
            }
        }
        else
        {
            EXCEPTION_THROW(EINVAL, "Branch \"%s\" already exists", args[0]);
            goto cleanup;
        }
    }

    minivcs_new_branch(args[0], &proj);

    cleanup:
    minivcs_destroy(&proj);
}

void cli_branch_delete(int argc, char** argv)
{
    const char* args[2];
    args[1] = def_proj_path;
    if(get_not_option(argc, argv, 2, args) < 1)
    {
        EXCEPTION_THROW(EINVAL, "%s", "Command requires arguments");
        return;
    }
    struct minivcs_project proj;
    minivcs_read_config(args[1], &proj);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    set_password(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    minivcs_open_from_config(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    bool agree = false;
    int opt;
    while((opt = getopt(argc, argv, "y")) != -1)
    {
        if(opt == 'y')
        {
            agree = true;
            break;
        }
    }
    if(!agree)
    {
        printf("All files stored in this branch will be deleted and can not be recovered!\n"
                       "Delete branch \"%s\"?[y/N] ", args[0]);
        if(!prompt_yes_no())
        {
            goto cleanup;
        }
    }

    minivcs_delete_branch(args[0], &proj);

    cleanup:
    minivcs_destroy(&proj);
}

void cli_branch_store(int argc, char** argv)
{
    const char* args[3];
    args[2] = def_proj_path;
    if(get_not_option(argc, argv, 3, args) < 2)
    {
        EXCEPTION_THROW(EINVAL, "%s", "Command requires arguments");
        return;
    }
    struct minivcs_project proj;
    minivcs_read_config(args[2], &proj);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    set_password(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    minivcs_open_from_config(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    bool agree = false;
    bool create = false;
    int opt;
    while((opt = getopt(argc, argv, "yn")) != -1)
    {
        if(opt == 'y')
        {
            agree = true;
        }
        else if(opt == 'n')
        {
            create = true;
        }
    }

    if(create)
    {
        if(branch_index_find(args[0], &proj.index))
        {
            EXCEPTION_THROW(EINVAL, "Branch %s already exists", args[0]);
            goto cleanup;
        }
        minivcs_new_branch(args[0], &proj);
        if(EXCEPTION_IS_THROWN)
        {
            goto cleanup;
        }
    }

    if(!agree && !create)
    {
        printf("Current branch state will be deleted including all obsolete files, and can not be recovered!\n"
               "Update branch \"%s\"?[y/N] ", args[0]);
        if(!prompt_yes_no())
        {
            goto cleanup;
        }
    }

    minivcs_update(args[0], args[1], &proj);

    cleanup:
    minivcs_destroy(&proj);
}

void cli_branch_extract(int argc, char** argv)
{
    const char* args[3];
    args[2] = def_proj_path;
    if(get_not_option(argc, argv, 3, args) < 2)
    {
        EXCEPTION_THROW(EINVAL, "%s", "Command requires arguments");
        return;
    }
    struct minivcs_project proj;
    minivcs_read_config(args[2], &proj);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    set_password(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    minivcs_open_from_config(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    minivcs_extract(args[0], args[1], &proj);

    cleanup:
    minivcs_destroy(&proj);
}

int main(int argc, char** argv)
{
    assert(argc > 0);
    if(argc < 2)
    {
        fprintf(stderr, "Command is required, use \"%s help\" for command formats", argv[0]);
        return 1;
    }

    if(strcmp(argv[1], help_cmd) == 0)
    {
        print_help(argv[0]);
        return 0;
    }

    if(argc < 3)
    {
        fprintf(stderr, "Command is required, use \"%s help\" for command formats", argv[0]);
        return 1;
    }

    EXCEPTION_CLEAR();

    for(const subcommand** scmd = cli_cmds; *scmd != NULL; ++scmd)
    {
        if(strcmp(argv[1], (*scmd)->command_str) == 0)
        {
            for(const command** cmd = (*scmd)->cmds; *cmd != NULL; ++cmd)
            {
                if(strcmp(argv[2], (*cmd)->command_str) == 0)
                {
                    (*cmd)->func(argc - 2, argv + 2);
                    goto found;
                }
            }
        }
    }

    fprintf(stderr, "Invalid command, use \"%s help\" for command formats", argv[0]);
    return 1;

    found:
    mem_cleanse(password, sizeof(password));
    if(EXCEPTION_IS_THROWN)
    {
        fprintf(stderr, "%s\n", EXCEPTION_MSG);
        return 1;
    }
    return 0;
}

