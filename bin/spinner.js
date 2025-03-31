import ora from 'ora';

export const spinner = {
    start: (text) => ora(text).start(),
    succeed: (spinner, text) => spinner.succeed(text),
    fail: (spinner, text) => spinner.fail(text),
    info: (spinner, text) => spinner.info(text)
};
