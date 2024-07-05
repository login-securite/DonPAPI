const config = {
    apiPath: import.meta.env.DEV ? location.protocol + '//' + '127.0.0.1' + ':8088' : location.protocol + '//' + location.host
}

export {config}