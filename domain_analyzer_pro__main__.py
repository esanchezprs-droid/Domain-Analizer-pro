from domain_analyzer_pro.analyzer import main, parse_arguments

if __name__ == "__main__":
    args = parse_arguments()
    main(args.domain or input("🔍 Ingrese el dominio a analizar: ").strip(),
         args.verbose, args.pdf)
