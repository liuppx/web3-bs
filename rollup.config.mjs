import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import json from "@rollup/plugin-json"
import typescript from '@rollup/plugin-typescript'

export default {
    input: './src/index.ts',
    output: [
        {
            file: 'dist/web3-bs.esm.js',
            format: 'esm',
            sourcemap: true,
        },
        {
            file: 'dist/web3-bs.umd.js',
            format: 'umd',
            name: 'YeYingWeb3',
            sourcemap: true,
        },
    ],
    onwarn(warning, warn) {
        if (warning.code === 'THIS_IS_UNDEFINED') return;
        warn(warning);
    },
    plugins: [
        typescript({include: ["src/**/*.ts"], exclude: ["node_modules", "**/*.ut.ts", "**/*.it.ts"]}),
        resolve({browser: true}),
        commonjs(),
        json()
    ],
    external: [], // 在这里添加你的外部依赖
};
