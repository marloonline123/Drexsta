import fs from 'node:fs/promises';

async function main() {
    try {
        const arData = await fs.readFile('../lang/ar.json', { encoding: 'utf8' });
        const enData = await fs.readFile('../lang/en.json', { encoding: 'utf8' });
        const parsedArData = JSON.parse(arData);
        const parsedEnData = JSON.parse(enData);

        await createDir();
        for (const key of Object.keys(parsedArData)) {
            await createFileWithContent('ar', key, parsedArData[key]);
        }
        for (const key of Object.keys(parsedEnData)) {
            await createFileWithContent('en', key, parsedEnData[key]);
        }

        // console.log(dir);
    } catch (err) {
        console.error(err);
    }
}

let num = 0;

async function createFileWithContent(lang, name, data) {
    try {
        const phpPrefix = '<?php \n\n\nreturn [ \n';
        let content = phpPrefix + '';
        content += toPhpArray(data);
        content += '\n];';
        // console.log('num: ', ++num + '- ' + name);
        
        // Note: fs.writeFile returns undefined on success, it doesn't return a file object.
        await fs.writeFile(`./lang/${lang}/${name}.php`, content || '', {
            flag: 'w+',
        });
    } catch (error) {
        console.error('Error create file or filling data: ', error);
    }
}

function toPhpArray(data, indent = 1) {
    try {
        if (typeof data === 'string') {
            // Escape single quotes for PHP safety
            // return `'${obj.replace(/'/g, "\\'")}'`;
            console.log('data is string ====== ', data);
            
        }

        if (typeof data !== 'object') {
            throw Error('Data is not object');
        }

        const space = ' '.repeat(indent * 4);
        const keys = Object.keys(data);

        if (keys.length <= 0) {
            return '';
        }

        const content = keys.map((key) => {
            
            if (typeof data[key] === 'string') {
                // console.log('should return: ', key);
                return `${space}"${key}" => "${data[key]}"`
            }
            console.log('should not return: ', key);

            const value = `${space}"${key}"` + " => [\n" + toPhpArray(data[key], indent + 1) + "\n" + space + "]";
            // console.log('value: ', data[key]);
            
            return value;
        });

        return content.join(",\n");
    } catch (error) {
        console.error('Error on transformaing to php array: ', error);
    }
}


async function createDir() {
    try {
        await fs.mkdir('./lang/en', { recursive: true });
        await fs.mkdir('./lang/ar', { recursive: true });
    } catch (error) {
        console.error('failed to to create dir: ', error);
    }
}
main();
